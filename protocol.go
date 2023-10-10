package tls_toy

import (
	"bytes"
	"encoding/binary"
)

type Encoder interface {
	Encode() []byte
}

// ////////////////// TLS Record Layer //////////////////
// TLS 协议最外层的 Record Layer

type ContentType uint8

const (
	ChangeCipherSpecContentType ContentType = 20
	AlertContentType            ContentType = 21
	HandshakeContentType        ContentType = 22
	ApplicationDataContentType  ContentType = 23
)

type ProtocolVersion struct {
	Major uint8
	Minor uint8
}

func (p *ProtocolVersion) Encode() []byte {
	return []byte{p.Major, p.Minor}
}

type TLSPlaintext struct {
	Type     ContentType
	Version  ProtocolVersion
	Length   uint16
	Fragment []byte
}

func (t *TLSPlaintext) Encode() []byte {
	b := bytes.NewBuffer([]byte{})
	binary.Write(b, binary.BigEndian, t.Type)
	b.Write(t.Version.Encode())
	binary.Write(b, binary.BigEndian, t.Length)
	b.Write(t.Fragment)
	return b.Bytes()
}

// ////////////////// TLS Handshake Protocol //////////////////
// TLS Handshake Protocol 用于建立 TLS 连接，报文的位置在Record Layer 的 Fragment 中

type HandshakeType uint8

// 握手类型
const (
	HelloRequestHandshakeType       HandshakeType = 0
	ClientHelloHandshakeType        HandshakeType = 1
	ServerHelloHandshakeType        HandshakeType = 2
	CertificateHandshakeType        HandshakeType = 11
	ServerKeyExchangeHandshakeType  HandshakeType = 12
	CertificateRequestHandshakeType HandshakeType = 13
	ServerHelloDoneHandshakeType    HandshakeType = 14
	CertificateVerifyHandshakeType  HandshakeType = 15
	ClientKeyExchangeHandshakeType  HandshakeType = 16
	FinishedHandshakeType           HandshakeType = 20
)

// Handshake
// 报文结构
type Handshake struct {
	MsgType HandshakeType
	Length  uint32 // 24 bits
	Body    Encoder
}

func (h *Handshake) Encode() []byte {
	b := bytes.NewBuffer([]byte{})
	binary.Write(b, binary.BigEndian, h.MsgType)
	h.Length = uint32(len(h.Body.Encode()))
	b.Write([]byte{byte(h.Length >> 16), byte(h.Length >> 8), byte(h.Length)})
	b.Write(h.Body.Encode())
	return b.Bytes()
}

// CipherSuite 加密套件
type CipherSuite uint16

type CompressionMethod uint8

type SessionID []byte

type Random struct {
	GMTUnixTime uint32
	RandomBytes [28]byte
}

func (r *Random) Encode() []byte {
	b := bytes.NewBuffer([]byte{})
	binary.Write(b, binary.BigEndian, r.GMTUnixTime)
	b.Write(r.RandomBytes[:])
	return b.Bytes()
}
