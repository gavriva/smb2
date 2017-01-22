package main

import (
	"fmt"
	"net"
	"os"

	"github.com/gavriva/smb2"
	"github.com/gavriva/smb2/plain"
)

const PORT = 445

func main() {
	//l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", PORT))
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", PORT))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Printf("Listening on %v port\n", PORT)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go smb2.HandleConnection(conn, func(user *smb2.User) ([]smb2.Tree, error) {
			p, err := plain.CreateTree(1, os.Args[1], os.Args[2])

			if err != nil {
				return nil, err
			}

			trees := make([]smb2.Tree, 1)
			trees[0] = p
			return trees, nil
		})
	}
}
