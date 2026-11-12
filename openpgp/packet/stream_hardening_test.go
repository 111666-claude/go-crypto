package packet

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// zeroReader is an io.Reader that yields an unbounded stream of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// A partial-length packet whose stream ends while a continuation length is
// expected is truncated and must not be reported as a clean EOF.
func TestPartialLengthReaderTruncatedContinuation(t *testing.T) {
	tests := []struct {
		hexInput  string
		hexOutput string
	}{
		// One chunk of one byte, then the stream ends without the
		// terminating length octet.
		{"e001", "01"},
		// One chunk of two bytes, then nothing.
		{"e10102", "0102"},
		// Two chunks, then a truncated (empty) continuation length.
		{"e0aae0bb", "aabb"},
	}
	for i, test := range tests {
		r := &partialLengthReader{readerFromHex(test.hexInput), 0, true}
		out, err := io.ReadAll(r)
		if err != io.ErrUnexpectedEOF {
			t.Errorf("%d: expected io.ErrUnexpectedEOF, got: %v", i, err)
		}
		if got := bytesToHex(out); got != test.hexOutput {
			t.Errorf("%d: got:%s want:%s", i, got, test.hexOutput)
		}
	}
}

// A partial-length packet terminated by a zero length must still end cleanly.
func TestPartialLengthReaderCleanTermination(t *testing.T) {
	r := &partialLengthReader{readerFromHex("e00100"), 0, true}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := bytesToHex(out); got != "01" {
		t.Fatalf("got:%s want:01", got)
	}
}

// A truncated literal data packet carried in partial-length chunks must
// surface io.ErrUnexpectedEOF to the caller reading the literal body.
func TestPartialLengthLiteralDataTruncated(t *testing.T) {
	// Literal data packet (tag 11), partial lengths:
	// chunk of 4: 'b', no filename, first two time bytes
	// chunk of 2: remaining time bytes
	// chunk of 2: body "AB"
	// then the stream ends without a terminating length.
	msg := readerFromHex("cb" + "e2" + "62000000" + "e1" + "0000" + "e1" + "4142")
	p, err := Read(msg)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	ld, ok := p.(*LiteralData)
	if !ok {
		t.Fatalf("expected *LiteralData, got %T", p)
	}
	body, err := io.ReadAll(ld.Body)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected io.ErrUnexpectedEOF, got: %v", err)
	}
	if string(body) != "AB" {
		t.Fatalf("got body %q, want %q", body, "AB")
	}
}

// A reader that returns io.EOF together with data must not cause the data to
// be dropped or the packet to end early.
func TestPartialLengthReaderEOFWithData(t *testing.T) {
	// One chunk of two bytes "0102" delivered with io.EOF, then a zero
	// length terminator.
	data := io.MultiReader(bytes.NewReader([]byte{0xe1}), &eofWithDataReader{data: []byte{0x01, 0x02}}, bytes.NewReader([]byte{0x00}))
	r := &partialLengthReader{data, 0, true}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, []byte{0x01, 0x02}) {
		t.Fatalf("got %x, want 0102", out)
	}
}

// eofWithDataReader returns its data together with io.EOF in a single Read.
type eofWithDataReader struct {
	data []byte
	done bool
}

func (r *eofWithDataReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.data), io.EOF
}

// Packets that are parsed into memory in one piece must respect the
// single-packet buffering budget, even when the declared length is backed by
// a (decompressed) stream that actually delivers the bytes.
func TestSinglePacketBufferingBudget(t *testing.T) {
	oversized := int64(maxBufferedPacketSize) + 1

	// UserId packet (tag 13) declaring maxBufferedPacketSize+1 content bytes.
	header := []byte{0xc0 | 13, 0xff, byte(oversized >> 24), byte(oversized >> 16), byte(oversized >> 8), byte(oversized)}
	body := io.LimitReader(zeroReader{}, oversized)
	_, err := Read(io.MultiReader(bytes.NewReader(header), body))
	if err != errors.ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got: %v", err)
	}

	// The same oversized packet read through an OpaqueReader must fail the
	// same way instead of buffering unboundedly.
	header[0] = 0xc0 | 2
	body = io.LimitReader(zeroReader{}, oversized)
	_, err = NewOpaqueReader(io.MultiReader(bytes.NewReader(header), body)).Next()
	if err != errors.ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got: %v", err)
	}
}

// Unknown non-critical packets must be skipped by the packet Reader, while
// unknown critical packets must surface an error.
func TestReaderUnknownPackets(t *testing.T) {
	literal := readerFromHex("cb08" + "620000000000" + "6869") // literal "hi"

	// Non-critical unknown packet (tag 40) followed by a literal packet.
	r := NewReader(io.MultiReader(readerFromHex("e802aabb"), literal))
	p, err := r.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.(*LiteralData); !ok {
		t.Fatalf("expected *LiteralData, got %T", p)
	}

	// Critical unknown packet (tag 39) must not be skipped.
	r = NewReader(readerFromHex("e702aabb"))
	_, err = r.Next()
	if _, ok := err.(errors.CriticalUnknownPacketTypeError); !ok {
		t.Fatalf("expected CriticalUnknownPacketTypeError, got: %v", err)
	}
}

// The packet Reader must bound the nesting depth of pushed readers.
func TestReaderPushDepthLimit(t *testing.T) {
	r := NewReader(bytes.NewReader(nil))
	for i := 0; i < maxReaders-1; i++ {
		if err := r.Push(bytes.NewReader(nil)); err != nil {
			t.Fatalf("push %d: unexpected error: %v", i, err)
		}
	}
	if err := r.Push(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected an error when exceeding the maximum reader depth")
	} else if !strings.Contains(err.Error(), "too many layers") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func bytesToHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(hexdigits[c>>4])
		sb.WriteByte(hexdigits[c&0x0f])
	}
	return sb.String()
}
