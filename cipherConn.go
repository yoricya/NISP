package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"time"
)

type cipheredConn struct {
	conn      net.Conn
	encrypter cipher.Stream
	decrypter cipher.Stream
}

// Реализация интерфейса net.Conn
func (c *cipheredConn) Read(b []byte) (n int, err error) {
	n, err = c.conn.Read(b)
	if n > 0 {
		c.decrypter.XORKeyStream(b[:n], b[:n])
	}
	return
}

func (c *cipheredConn) Write(b []byte) (n int, err error) {
	buf := make([]byte, len(b))
	c.encrypter.XORKeyStream(buf, b)
	return c.conn.Write(buf)
}

// Просто передаем остальные методы в оригинальное соединение
func (c *cipheredConn) Close() error                       { return c.conn.Close() }
func (c *cipheredConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *cipheredConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *cipheredConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *cipheredConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *cipheredConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func createCipheredStream(conn net.Conn, key []byte) (net.Conn, error) {
	// Генерируем случайный IV для шифрования
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Отправляем IV другой стороне
	if _, err := conn.Write(iv); err != nil {
		return nil, err
	}

	// Читаем IV от другой стороны
	otherIV := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(conn, otherIV); err != nil {
		return nil, err
	}

	// Создаем AES шифр
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Создаем шифраторы для чтения и записи
	// Для записи используем наш IV, для чтения - IV другой стороны
	encrypter := cipher.NewCFBEncrypter(block, iv)
	decrypter := cipher.NewCFBDecrypter(block, otherIV)

	return &cipheredConn{
		conn:      conn,
		encrypter: encrypter,
		decrypter: decrypter,
	}, nil
}
