package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
)

func main() {
	port := flag.String("port", "4040", "listening port")
	certFile := flag.String("cert", "./pengpengyangyang.cn_bundle.crt", "certificate PEM file")
	keyFile := flag.String("key", "./pengpengyangyang.cn.key", "key PEM file")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	cert1, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert, cert1}}

	log.Printf("listening on port %s\n", *port)
	l, err := tls.Listen("tcp", ":"+*port, config)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("accepted connection from %s\n", conn.RemoteAddr())

		go func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
			log.Printf("closing connection from %s\n", conn.RemoteAddr())
		}(conn)
	}
}
