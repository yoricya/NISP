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

	conn, e := net.Dial("tcp", "127.0.0.1:5585")
	//conn, e := net.Dial("tcp", "8.8.8.8:443")
	if e != nil {
		fmt.Println(e)
	}

	k, _, e := client_handshake(conn, -1)
	fmt.Println("Client shared key: " + hex.EncodeToString(k))
	fmt.Println(e)

	for true {
	}
}
