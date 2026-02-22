package shadowaead

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
)

// ErrShortPacket means that the packet is too short for a valid encrypted packet.
var ErrShortPacket = errors.New("short packet")

var _zerononce [128]byte // read-only. 128 bytes is more than enough.

// Pack encrypts plaintext using Cipher with a randomly generated salt and
// returns a slice of dst containing the encrypted packet and any error occurred.
// Ensure len(dst) >= ciph.SaltSize() + len(plaintext) + aead.Overhead().
func Pack(dst, plaintext []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	salt := dst[:saltSize]
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	aead, err := ciph.Encrypter(salt)
	if err != nil {
		return nil, err
	}

	if len(dst) < saltSize+len(plaintext)+aead.Overhead() {
		return nil, io.ErrShortBuffer
	}
	b := aead.Seal(dst[saltSize:saltSize], _zerononce[:aead.NonceSize()], plaintext, nil)
	return dst[:saltSize+len(b)], nil
}

// Unpack decrypts pkt using Cipher and returns a slice of dst containing the decrypted payload and any error occurred.
// ...
func Unpack(dst, pkt []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	if len(pkt) < saltSize {
		return nil, ErrShortPacket
	}
	salt := pkt[:saltSize]
	aead, err := ciph.Decrypter(salt)
	if err != nil {
		return nil, err
	}
	if len(pkt) < saltSize+aead.Overhead() {
		return nil, ErrShortPacket
	}
	// 确保 dst 缓冲区足够大以容纳解密后的明文
	// len(pkt) - saltSize - aead.Overhead() 是明文的长度
	if len(dst) < len(pkt)-saltSize-aead.Overhead() {
		return nil, io.ErrShortBuffer
	}
	b, err := aead.Open(dst[:0], _zerononce[:aead.NonceSize()], pkt[saltSize:], nil)
	return b, err
}

type packetConn struct {
	net.PacketConn
	Cipher
	pool sync.Pool // 使用 sync.Pool 替换 Mutex 和 buf
}

// NewPacketConn wraps a net.PacketConn with cipher
func NewPacketConn(c net.PacketConn, ciph Cipher) net.PacketConn {
	const maxPacketSize = 64 * 1024
	return &packetConn{
		PacketConn: c,
		Cipher:     ciph,
		pool: sync.Pool{ // 初始化缓冲区池
			New: func() interface{} {
				// 分配切片并返回指向它的指针
				b := make([]byte, maxPacketSize)
				return &b
			},
		},
	}
}

// WriteTo encrypts b and write to addr using the embedded PacketConn.
// 重构后：移除锁，使用 sync.Pool，实现并发安全和高效写入。
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// 从池中获取一个指向缓冲区的指针
	bufPtr := c.pool.Get().(*[]byte)
	defer c.pool.Put(bufPtr) // 确保将指针返回池中

	// 解引用指针以获取切片
	buf := *bufPtr

	// 将明文 b 加密到 buf 中
	packedBuf, err := Pack(buf, b, c)
	if err != nil {
		return 0, err
	}

	// 将加密后的数据（packedBuf 是 buf 的一个切片）发送出去
	_, err = c.PacketConn.WriteTo(packedBuf, addr)
	return len(b), err // 返回明文的长度
}

// ReadFrom reads from the embedded PacketConn and decrypts into b.
// 重构后：使用 sync.Pool 避免了额外的 copy()。
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// 从池中获取一个指向缓冲区的指针
	bufPtr := c.pool.Get().(*[]byte)
	defer c.pool.Put(bufPtr) // 确保将指针返回池中

	// 解引用指针以获取切片
	buf := *bufPtr

	// 将加密数据包读入临时缓冲区 buf
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}

	// 将 buf[:n] 中的加密数据解密到用户提供的缓冲区 b 中
	// Unpack 会将解密后的数据附加到 b[:0]
	bb, err := Unpack(b, buf[:n], c)
	if err != nil {
		return 0, addr, err
	}

	// bb 是 b 的一个切片，其长度为解密后的明文长度。
	return len(bb), addr, nil
}
