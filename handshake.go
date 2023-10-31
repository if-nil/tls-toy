package tls_toy

import (
	"bytes"
	"encoding/binary"
)

type HelloRequest struct {
	rawBytes []byte

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
	if len(h.rawBytes) != 0 {
		return h.rawBytes
	}
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

func (h *HelloRequest) Decode(b []byte) {
	h.rawBytes = b

	h.ClientVersion.Decode(b[0:2])
	h.Random.Decode(b[2:34])
	h.SessionLength = b[34]
	h.SessionID = b[35 : 35+h.SessionLength]
	h.CipherSuites = []CipherSuite{
		CipherSuite(binary.BigEndian.Uint16(b[35+h.SessionLength : 37+h.SessionLength])),
	}
	h.CompressionLength = b[37+h.SessionLength]
	h.Compression = []CompressionMethod{}
	for i := 0; i < int(h.CompressionLength); i++ {
		h.Compression = append(h.Compression, CompressionMethod(b[38+int(h.SessionLength)+int(h.CipherSuiteLength)+i]))
	}
	h.ExtensionsLength = binary.BigEndian.Uint16(b[38+int(h.SessionLength)+int(h.CompressionLength) : 40+int(h.SessionLength)+int(h.CompressionLength)])
	h.Extensions = b[40+int(h.SessionLength)+int(h.CompressionLength) : 40+int(h.SessionLength)+int(h.CompressionLength)+int(h.ExtensionsLength)]
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
	c.CipherSuitesLength = uint16(len(c.CipherSuites) * 2)
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

func (c *ClientHello) Decode(b []byte) {
	c.ClientVersion.Decode(b[0:2])
	c.Random.Decode(b[2:34])
	c.SessionLength = b[34]
	c.SessionID = b[35 : 35+c.SessionLength]
	c.CipherSuitesLength = binary.BigEndian.Uint16(b[35+c.SessionLength : 37+c.SessionLength])
	c.CipherSuites = []CipherSuite{}
	for i := 0; i < int(c.CipherSuitesLength); i += 2 {
		c.CipherSuites = append(c.CipherSuites, CipherSuite(binary.BigEndian.Uint16(b[37+c.SessionLength+uint8(i):39+c.SessionLength+uint8(i)])))
	}
	c.CompressionLength = b[37+uint16(c.SessionLength)+c.CipherSuitesLength]
	c.Compression = []CompressionMethod{}
	for i := 0; i < int(c.CompressionLength); i++ {
		c.Compression = append(c.Compression, CompressionMethod(b[38+uint16(c.SessionLength)+c.CipherSuitesLength+uint16(i)]))
	}
	c.ExtensionsLength = binary.BigEndian.Uint16(b[38+uint16(c.SessionLength)+c.CipherSuitesLength+uint16(c.CompressionLength) : 40+uint16(c.SessionLength)+c.CipherSuitesLength+uint16(c.CompressionLength)])
	c.Extensions = b[40+uint16(c.SessionLength)+c.CipherSuitesLength+uint16(c.CompressionLength) : 40+uint16(c.SessionLength)+c.CipherSuitesLength+uint16(c.CompressionLength)+c.ExtensionsLength]
}

type ServerHello struct {
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

func (s ServerHello) Encode() []byte {
	return nil
}

func (s ServerHello) Decode(b []byte) {
}

type Certificates struct {
	rawBytes []byte

	CertificatesLength uint32
	Certificates       []Certificate
}

func (c *Certificates) Encode() []byte {
	if len(c.rawBytes) != 0 {
		return c.rawBytes
	}
	b := bytes.NewBuffer([]byte{})
	binary.Write(b, binary.BigEndian, c.CertificatesLength)
	for _, certificates := range c.Certificates {
		binary.Write(b, binary.BigEndian, certificates.Encode())
	}
	return b.Bytes()
}

func (c *Certificates) Decode(b []byte) {
	c.rawBytes = b

	c.CertificatesLength = uint32(b[0])<<16 + uint32(b[1])<<8 + uint32(b[2])
	c.Certificates = []Certificate{}
	length := 0
	for length < int(c.CertificatesLength) {
		certificates := Certificate{}
		certificates.Decode(b[3+length:])
		c.Certificates = append(c.Certificates, certificates)
		length += 3 + int(certificates.CertificatesLength)
	}
}

type Certificate struct {
	CertificatesLength uint32
	Certificate        []byte
}

func (c *Certificate) Encode() []byte {
	return nil
}

func (c *Certificate) Decode(b []byte) {
	c.CertificatesLength = uint32(b[0])<<16 + uint32(b[1])<<8 + uint32(b[2])
	c.Certificate = b[3 : 3+c.CertificatesLength]
}

type ECServerParams struct {
	rawByte []byte

	Raw                []byte
	CurveType          uint8
	NamedCurve         uint16
	PubkeyLen          uint8
	Pubkey             []byte
	AlgorithmHash      uint8
	AlgorithmSignature uint8
	SigLen             uint16
	Sig                []byte
}

func (e *ECServerParams) Encode() []byte {
	return e.rawByte
}

func (e *ECServerParams) Decode(b []byte) {
	e.rawByte = b

	e.CurveType = b[0]
	e.NamedCurve = binary.BigEndian.Uint16(b[1:3])
	e.PubkeyLen = b[3]
	e.Pubkey = b[4 : 4+e.PubkeyLen]
	e.AlgorithmHash = b[4+e.PubkeyLen]
	e.AlgorithmSignature = b[5+e.PubkeyLen]
	e.SigLen = binary.BigEndian.Uint16(b[6+e.PubkeyLen : 8+e.PubkeyLen])
	e.Sig = b[8+e.PubkeyLen : 8+uint16(e.PubkeyLen)+e.SigLen]
	e.Raw = b[:4+uint16(e.PubkeyLen)]
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
	PubkeyLen uint8
	Pubkey    []byte
}

func (c *ClientKeyExchange) Encode() []byte {
	b := bytes.NewBuffer([]byte{})
	binary.Write(b, binary.BigEndian, c.PubkeyLen)
	b.Write(c.Pubkey)
	return b.Bytes()
}

func (c *ClientKeyExchange) Decode(b []byte) {
	c.PubkeyLen = b[0]
	c.Pubkey = b[1 : 1+c.PubkeyLen]
}

type ChangeCipherSpec uint8

func (c *ChangeCipherSpec) Encode() []byte {
	b := bytes.NewBuffer([]byte{})
	binary.Write(b, binary.BigEndian, uint8(*c))
	return b.Bytes()
}

func (c *ChangeCipherSpec) Decode(b []byte) {
	*c = ChangeCipherSpec(binary.BigEndian.Uint16(b))
}

type Finished []byte

func (f *Finished) Encode() []byte {
	return *f
}

func (f *Finished) Decode(b []byte) {
	*f = b
}
