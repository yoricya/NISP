package main

import "time"

// generatePrivateKey генерирует случайный приватный ключ
func generatePrivateKey(max int) int {
	// Простой способ получить случайное число от 1 до max-1
	return int(time.Now().UnixNano()%int64(max-1)) + 1
}

// computePublicKey вычисляет публичный ключ: g^privateKey mod p
func computePublicKey(g, privateKey, p int) int {
	result := 1
	for i := 0; i < privateKey; i++ {
		result = (result * g) % p
	}
	return result
}

// computeSharedSecret вычисляет общий секрет: otherPublicKey^privateKey mod p
func computeSharedSecret(otherPublicKey, privateKey, p int) int {
	result := 1
	for i := 0; i < privateKey; i++ {
		result = (result * otherPublicKey) % p
	}
	return result
}
