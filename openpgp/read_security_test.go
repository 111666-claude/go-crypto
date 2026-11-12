package openpgp

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func secPacketLength(n int) []byte {
	switch {
	case n < 192:
		return []byte{byte(n)}
	case n < 8384:
		n -= 192
		return []byte{byte(n>>8) + 192, byte(n)}
	default:
		return []byte{0xff, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func secWrapPacket(tag byte, body []byte) []byte {
	out := []byte{0xc0 | tag}
	out = append(out, secPacketLength(len(body))...)
	return append(out, body...)
}

func secOnePassSig(keyId uint64) []byte {
	var body bytes.Buffer
	body.WriteByte(0x03)
	body.WriteByte(0x00)
	body.WriteByte(0x08)
	body.WriteByte(0x01)
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], keyId)
	body.Write(id[:])
	body.WriteByte(0x01)
	return secWrapPacket(4, body.Bytes())
}

func secLiteral(data []byte) []byte {
	var body bytes.Buffer
	body.WriteByte('b')
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x00, 0x00, 0x00})
	body.Write(data)
	return secWrapPacket(11, body.Bytes())
}

func secSigNoIssuer() []byte {
	creation := []byte{0x05, 0x02, 0x00, 0x00, 0x00, 0x01}
	var body bytes.Buffer
	body.WriteByte(0x04)
	body.WriteByte(0x00)
	body.WriteByte(0x01)
	body.WriteByte(0x08)
	binary.Write(&body, binary.BigEndian, uint16(len(creation)))
	body.Write(creation)
	binary.Write(&body, binary.BigEndian, uint16(0))
	body.Write([]byte{0x00, 0x00})
	body.Write([]byte{0x00, 0x00})
	return secWrapPacket(2, body.Bytes())
}

func TestReadV1NilIssuerNoPanic(t *testing.T) {
	entity, err := NewEntity("test", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, ok := entity.SigningKey(time.Now())
	if !ok {
		t.Fatal("no signing key")
	}

	var msg []byte
	msg = append(msg, secOnePassSig(signingKey.PublicKey.KeyId)...)
	msg = append(msg, secLiteral([]byte("hello"))...)
	msg = append(msg, secSigNoIssuer()...)

	md, err := ReadMessage(bytes.NewReader(msg), EntityList{entity}, nil, nil)
	if err != nil {
		return
	}
	io.Copy(io.Discard, md.UnverifiedBody)
}

type secNopWriteCloser struct{ io.Writer }

func (secNopWriteCloser) Close() error { return nil }

// secCompress wraps the given packet bytes in a ZLIB compressed packet.
func secCompress(t *testing.T, inner []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := packet.SerializeCompressed(secNopWriteCloser{&buf}, packet.CompressionZLIB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A compressed message that decompresses to more than the configured
// MaxDecompressedMessageSize must fail with ErrMessageTooLarge.
func TestReadMessageDecompressionBombLimit(t *testing.T) {
	data := bytes.Repeat([]byte("A"), 2<<20) // 2 MiB, compresses to ~2 KiB
	msg := secCompress(t, secLiteral(data))

	limit := int64(1 << 20)
	config := &packet.Config{MaxDecompressedMessageSize: &limit}
	md, err := ReadMessage(bytes.NewReader(msg), nil, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(md.UnverifiedBody); err != errors.ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got: %v", err)
	}

	// The same message without a limit reads fine.
	md, err = ReadMessage(bytes.NewReader(msg), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, data) {
		t.Fatal("decompressed body does not match original data")
	}
}

// Nested compressed packets must draw from a single shared output budget:
// each layer below stays under the limit on its own, but their combined
// decompressed output exceeds it.
func TestReadMessageNestedCompressionSharedBudget(t *testing.T) {
	data := bytes.Repeat([]byte("A"), 1<<20) // 1 MiB, compresses to ~1 KiB
	inner := secCompress(t, secLiteral(data))
	msg := secCompress(t, inner)

	// Larger than either layer's own decompressed output, smaller than the
	// sum of both layers.
	limit := int64(1<<20) + int64(len(inner))/2
	config := &packet.Config{MaxDecompressedMessageSize: &limit}
	md, err := ReadMessage(bytes.NewReader(msg), nil, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(md.UnverifiedBody); err != errors.ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got: %v", err)
	}

	// With a budget covering the combined output the message reads fine.
	limit = int64(1<<20) + int64(len(inner)) + 1024
	md, err = ReadMessage(bytes.NewReader(msg), nil, nil, config)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, data) {
		t.Fatal("decompressed body does not match original data")
	}
}

// A Signature packet that is not announced by a OnePassSignature packet must
// not be silently dropped, which would downgrade a signed message to an
// unsigned one.
func TestReadMessageSignatureBeforeLiteralFails(t *testing.T) {
	msg := append(secSigNoIssuer(), secLiteral([]byte("a"))...)
	_, err := ReadMessage(bytes.NewReader(msg), nil, nil, nil)
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("expected StructuralError, got: %v", err)
	}
	if !strings.Contains(string(structural), "before literal data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Only Signature (and Padding) packets may follow the LiteralData of a signed
// message; anything else must surface an error while reading the body.
func TestReadMessageUnexpectedPacketAfterLiteral(t *testing.T) {
	msg := secOnePassSig(0)
	msg = append(msg, secLiteral([]byte("a"))...)
	msg = append(msg, secLiteral([]byte("b"))...)

	md, err := ReadMessage(bytes.NewReader(msg), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(md.UnverifiedBody)
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("expected StructuralError, got: %v", err)
	}
	if !strings.Contains(string(structural), "unexpected packet after literal data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Padding packets after the signature are legal and must be accepted.
func TestReadMessagePaddingAfterSignature(t *testing.T) {
	msg := secOnePassSig(0)
	msg = append(msg, secLiteral([]byte("a"))...)
	msg = append(msg, secSigNoIssuer()...)
	msg = append(msg, 0xc0|21, 0x03, 0x00, 0x00, 0x00) // padding packet

	md, err := ReadMessage(bytes.NewReader(msg), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "a" {
		t.Fatalf("got body %q, want %q", body, "a")
	}
}

// Unknown non-critical packets in a message must be skipped; unknown critical
// packets must surface an error.
func TestReadMessageUnknownPackets(t *testing.T) {
	// Non-critical unknown packet (tag 40) before the literal data.
	msg := []byte{0xc0 | 40, 0x02, 0xaa, 0xbb}
	msg = append(msg, secLiteral([]byte("hi"))...)
	md, err := ReadMessage(bytes.NewReader(msg), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hi" {
		t.Fatalf("got body %q, want %q", body, "hi")
	}

	// Critical unknown packet (tag 39) must not be skipped.
	msg = []byte{0xc0 | 39, 0x02, 0xaa, 0xbb}
	msg = append(msg, secLiteral([]byte("hi"))...)
	_, err = ReadMessage(bytes.NewReader(msg), nil, nil, nil)
	if _, ok := err.(errors.CriticalUnknownPacketTypeError); !ok {
		t.Fatalf("expected CriticalUnknownPacketTypeError, got: %v", err)
	}
}
