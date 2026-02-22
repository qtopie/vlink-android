package shadowaead

import (
	"bufio" // Added for bufio.NewReader
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
)

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1

type writer struct {
	io.Writer
	cipher.AEAD
	nonce []byte
	buf   []byte
}

// NewWriter wraps an io.Writer with AEAD encryption.
func NewWriter(w io.Writer, aead cipher.AEAD) io.Writer { return newWriter(w, aead) }

func newWriter(w io.Writer, aead cipher.AEAD) *writer {
	return &writer{
		Writer: w,
		AEAD:   aead,
		// Buffer large enough for one full packet:
		// [2-byte size][size overhead] + [max payload][payload overhead]
		buf:   make([]byte, 2+aead.Overhead()+payloadSizeMask+aead.Overhead()),
		nonce: make([]byte, aead.NonceSize()),
	}
}

// Write encrypts b and writes to the embedded io.Writer.
//
// This method is refactored to be highly efficient.
// It avoids the original's bytes.NewBuffer allocation for every call.
// It chunks the input buffer `b`, encrypts, and writes directly.
// It also avoids an intermediate copy by sealing from `b` (payload)
// directly into `w.buf` (the packet buffer).
func (w *writer) Write(b []byte) (n int, err error) {
	for len(b) > 0 {
		// Determine the size of the next chunk
		chunkSize := payloadSizeMask
		if len(b) < payloadSizeMask {
			chunkSize = len(b)
		}
		payload := b[:chunkSize] // This is the plaintext payload slice

		// Get the full packet buffer
		buf := w.buf

		// 1. Write and encrypt the 2-byte payload size
		buf[0], buf[1] = byte(chunkSize>>8), byte(chunkSize)
		w.Seal(buf[:0], w.nonce, buf[:2], nil) // Encrypts in-place
		increment(w.nonce)

		// 2. Encrypt the payload
		// We encrypt from the source `payload` slice directly into the
		// destination buffer `buf` at the correct offset, avoiding a copy.
		payloadDst := buf[2+w.Overhead() : 2+w.Overhead()] // Slice anchor
		w.Seal(payloadDst[:0], w.nonce, payload, nil)
		increment(w.nonce)

		// 3. Write the full packet (encrypted size + encrypted payload)
		// The total packet size is the sum of its encrypted parts.
		packetSize := (2 + w.Overhead()) + (chunkSize + w.Overhead())
		_, ew := w.Writer.Write(buf[:packetSize])
		if ew != nil {
			return n, ew
		}

		// Advance
		n += chunkSize
		b = b[chunkSize:]
	}

	return n, nil
}

// ReadFrom reads from the given io.Reader until EOF or error, encrypts and
// writes to the embedded io.Writer. Returns number of bytes read from r and
// any error encountered.
//
// This implementation is already efficient (zero-copy read into w.buf),
// so it remains unchanged.
func (w *writer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		buf := w.buf
		// payloadBuf is the slice where *plaintext* will be read into
		payloadBuf := buf[2+w.Overhead() : 2+w.Overhead()+payloadSizeMask]
		nr, er := r.Read(payloadBuf)

		if nr > 0 {
			n += int64(nr)
			// Resize buf to the full packet size for this chunk
			buf = buf[:2+w.Overhead()+nr+w.Overhead()]
			// Resize payloadBuf to the actual plaintext size
			payloadBuf = payloadBuf[:nr]

			// 1. Write and encrypt payload size
			buf[0], buf[1] = byte(nr>>8), byte(nr) // big-endian payload size
			w.Seal(buf[:0], w.nonce, buf[:2], nil)
			increment(w.nonce)

			// 2. Encrypt payload (which is already in-place in payloadBuf)
			w.Seal(payloadBuf[:0], w.nonce, payloadBuf, nil)
			increment(w.nonce)

			// 3. Write the full packet
			_, ew := w.Writer.Write(buf)
			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			break
		}
	}

	return n, err
}

type reader struct {
	io.Reader // Now expected to be a bufio.Reader
	cipher.AEAD
	nonce    []byte
	buf      []byte // Buffer for *one* encrypted payload
	leftover []byte
}

// NewReader wraps an io.Reader with AEAD decryption.
func NewReader(r io.Reader, aead cipher.AEAD) io.Reader { return newReader(r, aead) }

// newReader is refactored to wrap the provided io.Reader with a
// bufio.NewReader. This coalesces the two small `read` calls
// in `reader.read()` (one for header, one for payload) into
// fewer, larger, and more efficient reads from the underlying stream.
func newReader(r io.Reader, aead cipher.AEAD) *reader {
	return &reader{
		Reader: bufio.NewReader(r), // Wrap in a buffered reader
		AEAD:   aead,
		buf:    make([]byte, payloadSizeMask+aead.Overhead()),
		nonce:  make([]byte, aead.NonceSize()),
	}
}

// read and decrypt a record into the internal buffer. Return decrypted payload length and any error encountered.
// This function is unchanged, but it will now read from the bufio.Reader,
// which makes it much more efficient.
func (r *reader) read() (int, error) {
	// decrypt payload size
	// This first ReadFull will trigger a larger read (e.g., 4KB)
	// from the underlying net.Conn into the bufio.Reader's buffer.
	buf := r.buf[:2+r.Overhead()]
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	size := (int(buf[0])<<8 + int(buf[1])) & payloadSizeMask

	// decrypt payload
	// This second ReadFull will now read from the bufio.Reader's
	// buffer first, before hitting the net.Conn again.
	buf = r.buf[:size+r.Overhead()]
	_, err = io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to b.
func (r *reader) Read(b []byte) (int, error) {
	// copy decrypted bytes (if any) from previous record first
	if len(r.leftover) > 0 {
		n := copy(b, r.leftover)
		r.leftover = r.leftover[n:]
		return n, nil
	}

	n, err := r.read() // This still calls the same method
	m := copy(b, r.buf[:n])
	if m < n { // insufficient len(b), keep leftover for next read
		r.leftover = r.buf[m:n]
	}
	return m, err
}

// WriteTo reads from the embedded io.Reader, decrypts and writes to w until
// there's no more data to write or when an error occurs. Return number of
// bytes written to w and any error encountered.
func (r *reader) WriteTo(w io.Writer) (n int64, err error) {
	// write decrypted bytes left over from previous record
	for len(r.leftover) > 0 {
		nw, ew := w.Write(r.leftover)
		r.leftover = r.leftover[nw:]
		n += int64(nw)
		if ew != nil {
			return n, ew
		}
	}

	for {
		nr, er := r.read() // This benefits from bufio.Reader
		if nr > 0 {
			nw, ew := w.Write(r.buf[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract (using src.WriteTo shortcut)
				err = er
			}
			break
		}
	}

	return n, err
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

type streamConn struct {
	net.Conn
	Cipher
	r *reader
	w *writer
}

func (c *streamConn) initReader() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, err := c.Decrypter(salt)
	if err != nil {
		return err
	}
	// newReader now returns a buffered reader
	c.r = newReader(c.Conn, aead)
	return nil
}

func (c *streamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *streamConn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *streamConn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	aead, err := c.Encrypter(salt)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}
	c.w = newWriter(c.Conn, aead)
	return nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	// This now calls the new, efficient Write method
	return c.w.Write(b)
}

func (c *streamConn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	// This calls the (already efficient) ReadFrom method
	return c.w.ReadFrom(r)
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph Cipher) net.Conn { return &streamConn{Conn: c, Cipher: ciph} }
