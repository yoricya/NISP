package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	rand2 "math/rand"
	"net"
)

// (Условия рукопожатия создает клиент)

// Клиентская часть рукопожатия
func client_handshake(conn net.Conn, uniqueID int64) ([]byte, net.Conn, error) {
	hash, e := start_client_handshake(conn, uniqueID)
	if e != nil {
		return nil, nil, e
	}

	cipConn, err := createCipheredStream(conn, hash)
	if err != nil {
		return nil, nil, err
	}

	check_client_handshake(cipConn)

	return hash, cipConn, nil
}

func start_client_handshake(conn net.Conn, uniqueID int64) ([]byte, error) {
	//_________________________ Шаг 1 (Отправляем параметры)

	// Отправляем 2 пустых байта
	conn.Write(make([]byte, 2))

	// Отправляем простое число
	prime := rand2.Intn(10000)

	prime_b := make([]byte, 8)
	binary.LittleEndian.PutUint64(prime_b, uint64(prime))
	conn.Write(prime_b)

	// Отправляем 4 пустых байта
	conn.Write(make([]byte, 4))

	// Отправляем генератор
	generator := 5
	gen_b := make([]byte, 8)
	binary.LittleEndian.PutUint64(gen_b, uint64(generator))
	conn.Write(gen_b)

	// Отправляем uniqueId
	unique_b := make([]byte, 8)
	binary.LittleEndian.PutUint64(unique_b, uint64(uniqueID))
	conn.Write(unique_b)

	//_________________________ Шаг 2 (Получаем ключ сервера)

	srv_dat := make([]byte, 2)
	conn.Read(srv_dat)

	if srv_dat[0] > 10 {
		return nil, errors.New("server maybe dont support nisp")
	}

	if srv_dat[1] > 10 {
		return nil, errors.New("server maybe dont support nisp")
	}

	// Читаем открытый ключ сервера
	spub_b := make([]byte, 8)
	conn.Read(spub_b)
	serverPublicKey := int(binary.LittleEndian.Uint64(spub_b))

	//_________________________ Шаг 3 (Отправляем свой ключ)

	// Генерируем закрытый ключ
	clientPrivateKey := generatePrivateKey(prime)

	// Вычисляем открытый ключ
	clientPublicKey := computePublicKey(generator, clientPrivateKey, prime)

	// Отправляем открытый ключ
	conn.Write(make([]byte, 2))
	cpub_b := make([]byte, 8)
	binary.LittleEndian.PutUint64(cpub_b, uint64(clientPublicKey))
	conn.Write(cpub_b)

	//_________________________ Шаг 4 (Генерируем общий ключ)

	sharedSecret := computeSharedSecret(serverPublicKey, clientPrivateKey, prime)
	sharedSecret_b := make([]byte, 8)
	binary.LittleEndian.PutUint64(sharedSecret_b, uint64(sharedSecret))

	// Получаем финальный ключ через SHA256
	hash := sha256.Sum256(sharedSecret_b)
	return hash[:], nil
}

func check_client_handshake(conn net.Conn) {
	//Get control number
	control_number_b := make([]byte, 8)
	conn.Read(control_number_b)
	num := binary.LittleEndian.Uint64(control_number_b) + 444

	//Send control number
	control_number_b = make([]byte, 8)
	binary.LittleEndian.PutUint64(control_number_b, num)
	conn.Write(control_number_b)
}
