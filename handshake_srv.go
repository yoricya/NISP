package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	rand2 "math/rand"
	"net"
)

type NISPServerConnect struct {
	sharedKey    []byte
	originalConn net.Conn
	securedConn  net.Conn
	clientID     int64
}

// (Условия рукопожатия создает клиент)

// Серверная часть рукопожатия
func srv_handshake(conn net.Conn) (*NISPServerConnect, error) {
	clientid, key, err := start_srv_handshake(conn)
	if err != nil {
		return nil, err
	}

	cipConn, e := createCipheredStream(conn, key)
	if e != nil {
		return nil, e
	}

	if !check_server_handshake(cipConn) {
		return nil, errors.New("server handshake failed")
	}

	nisp := &NISPServerConnect{
		sharedKey:    key,
		originalConn: conn,
		securedConn:  cipConn,
		clientID:     clientid,
	}

	return nisp, nil
}

func start_srv_handshake(conn net.Conn) (int64, []byte, error) {
	//_________________________ Шаг 1 (Получаем параметры)

	// Пропускаем 2 байта
	conn.Read(make([]byte, 2))

	// Читаем простое число
	prime_b := make([]byte, 8)
	conn.Read(prime_b)
	prime := int(binary.LittleEndian.Uint64(prime_b))

	// Пропускаем 4 байта
	conn.Read(make([]byte, 4))

	// Читаем генератор
	gen_b := make([]byte, 8)
	conn.Read(gen_b)
	generator := int(binary.LittleEndian.Uint64(gen_b))

	// Читаем uniqueID
	uniqId_b := make([]byte, 8)
	conn.Read(uniqId_b)
	clid := int(binary.LittleEndian.Uint64(uniqId_b))

	if clid == 0 {
		return 0, nil, errors.New("uniqueID is zero")
	}

	//_________________________ Шаг 2 (Создаем ключи сервера)

	// Генерируем закрытый ключ
	serverPrivateKey := generatePrivateKey(prime)

	// Вычисляем открытый ключ
	serverPublicKey := computePublicKey(generator, serverPrivateKey, prime)

	// Отправляем открытый ключ
	conn.Write(make([]byte, 2))
	spub_b := make([]byte, 8)
	binary.LittleEndian.PutUint64(spub_b, uint64(serverPublicKey))
	conn.Write(spub_b)

	//_________________________ Шаг 3 (Получаем ключ клиента)

	// Пропускаем 2 байта
	conn.Read(make([]byte, 2))

	// Читаем открытый ключ клиента
	cpub_b := make([]byte, 8)
	conn.Read(cpub_b)
	clientPublicKey := int(binary.LittleEndian.Uint64(cpub_b))

	//_________________________ Шаг 4 (Генерируем общий ключ)

	sharedSecret := computeSharedSecret(clientPublicKey, serverPrivateKey, prime)
	sharedSecret_b := make([]byte, 8)
	binary.LittleEndian.PutUint64(sharedSecret_b, uint64(sharedSecret))

	// Получаем финальный ключ через SHA256
	hash := sha256.Sum256(sharedSecret_b)
	return int64(clid), hash[:], nil
}

func check_server_handshake(conn net.Conn) bool {
	control_number := rand2.Uint64()

	//Send control number
	control_number_b := make([]byte, 8)
	binary.LittleEndian.PutUint64(control_number_b, control_number)
	conn.Write(control_number_b)

	//Get control number from client
	control_number_b = make([]byte, 8)
	conn.Read(control_number_b)

	return binary.LittleEndian.Uint64(control_number_b) == control_number+444
}
