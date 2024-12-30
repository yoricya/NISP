package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

func main() {

	fmt.Println("started")

	ls, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5585})
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for true {
			conn, err := ls.Accept()
			if err != nil {
				log.Println(err)
			}

			nisp, err := srv_handshake(conn)
			if err != nil {
				log.Println(err)
			} else {
				fmt.Println("Server shared key: " + hex.EncodeToString(nisp.sharedKey))
			}
		}
	}()

	k := make([]byte, 1)

	// First handshake
	{
		conn, e := net.Dial("tcp", "127.0.0.1:5585")
		//conn, e := net.Dial("tcp", "192.168.0.1:80")
		if e != nil {
			fmt.Println(e)
		}

		k, _, e = client_handshake(conn, 1, nil)
		fmt.Println("Client shared key: " + hex.EncodeToString(k))
		fmt.Println(e)

		conn.Close()
	}

	// Restore connect
	{
		conn, e := net.Dial("tcp", "127.0.0.1:5585")
		//conn, e := net.Dial("tcp", "192.168.0.1:80")
		if e != nil {
			fmt.Println(e)
		}

		k, _, e := client_handshake(conn, 1, k)
		fmt.Println("Client shared key: " + hex.EncodeToString(k))
		fmt.Println(e)

		conn.Close()
	}

	for true {
	}
}
