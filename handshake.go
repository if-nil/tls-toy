package tls_toy

import (
	"bytes"
	"encoding/binary"
)

type HelloRequest struct {
	ClientVersion     ProtocolVersion
	Random            Random
	SessionLength     uint8
	SessionID         SessionID
	CipherSuiteLength uint16
	CipherSuites      []CipherSuite
	CompressionLength uint8
	Compression       []CompressionMethod
	ExtensionsLength  uint16
	Extensions        []byte
}

func (h *HelloRequest) Encode() []byte {
	b := bytes.NewBuffer([]byte{})
	b.Write(h.ClientVersion.Encode())
	b.Write(h.Random.Encode())
	binary.Write(b, binary.BigEndian, h.SessionLength)
	b.Write(h.SessionID)
	binary.Write(b, binary.BigEndian, h.CipherSuiteLength)
	for _, cipherSuite := range h.CipherSuites {
		binary.Write(b, binary.BigEndian, cipherSuite)
	}
	binary.Write(b, binary.BigEndian, h.CompressionLength)
	for _, compression := range h.Compression {
		binary.Write(b, binary.BigEndian, compression)
	}
	binary.Write(b, binary.BigEndian, h.ExtensionsLength)
	b.Write(h.Extensions)
	return b.Bytes()
}

type ClientHello struct {
	ClientVersion      ProtocolVersion
	Random             Random
	SessionLength      uint8
	SessionID          SessionID
	CipherSuitesLength uint16
	CipherSuites       []CipherSuite
	CompressionLength  uint8
	Compression        []CompressionMethod
	ExtensionsLength   uint16
	Extensions         []byte
}

func (c *ClientHello) Encode() []byte {
	b := bytes.NewBuffer([]byte{})
	b.Write(c.ClientVersion.Encode())
	b.Write(c.Random.Encode())
	binary.Write(b, binary.BigEndian, c.SessionLength)
	b.Write(c.SessionID)
	binary.Write(b, binary.BigEndian, c.CipherSuitesLength)
	for _, cipherSuite := range c.CipherSuites {
		binary.Write(b, binary.BigEndian, cipherSuite)
	}
	binary.Write(b, binary.BigEndian, c.CompressionLength)
	for _, compression := range c.Compression {
		binary.Write(b, binary.BigEndian, compression)
	}
	binary.Write(b, binary.BigEndian, c.ExtensionsLength)
	b.Write(c.Extensions)
	return b.Bytes()
}

type ServerHello struct {
}

type Certificate struct {
}

type ServerKeyExchange struct {
}

type CertificateRequest struct {
}

type ServerHelloDone struct {
}

type CertificateVerify struct {
}

type ClientKeyExchange struct {
}

type Finished struct {
}
