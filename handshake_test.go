package tls_toy

import (
	"net"
	"testing"
)

func TestClientHello(t *testing.T) {
	clientHello := &ClientHello{
		ClientVersion: ProtocolVersion{0x03, 0x03},
		Random: Random{
			GMTUnixTime: 0x649ebde5,
			RandomBytes: [28]byte{0x81, 0xf1, 0x6d, 0x49, 0x06, 0xae, 0x05, 0x13, 0x36, 0x96, 0xaa, 0xfc, 0xb7, 0x8e, 0xe7, 0x68, 0x4e, 0x3d, 0x0a, 0x4b, 0xff, 0xbf, 0xad, 0x0e, 0x8a, 0x9b, 0xf4, 0xaf},
			// RandomBytes: func() [28]byte {
			// 	randomBytes := make([]byte, 28)
			// 	rand.Read(randomBytes)
			// 	var random [28]byte
			// 	copy(random[:], randomBytes)
			// 	return random
			// }(),
		},
		SessionLength: 0,
		// SessionID: func() []byte {
		// 	sessionID := make([]byte, 32)
		// 	rand.Read(sessionID)
		// 	return sessionID
		// }(),

		CipherSuitesLength: 0,
		CipherSuites: []CipherSuite{
			// CipherSuite(TLS_NULL_WITH_NULL_NULL),
			// CipherSuite(TLS_RSA_WITH_RC4_128_SHA),

			CipherSuite(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
			CipherSuite(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
			CipherSuite(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
			CipherSuite(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_256_CCM),
			CipherSuite(TLS_DHE_RSA_WITH_AES_256_CCM),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
			CipherSuite(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
			CipherSuite(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
			CipherSuite(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
			CipherSuite(TLS_DHE_RSA_WITH_AES_256_CBC_SHA),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8),
			CipherSuite(TLS_DHE_RSA_WITH_AES_256_CCM_8),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384),
			CipherSuite(TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384),
			CipherSuite(TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384),
			CipherSuite(TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384),
			CipherSuite(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256),
			CipherSuite(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			CipherSuite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
			CipherSuite(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_128_CCM),
			CipherSuite(TLS_DHE_RSA_WITH_AES_128_CCM),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
			CipherSuite(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
			CipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
			CipherSuite(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
			CipherSuite(TLS_DHE_RSA_WITH_AES_128_CBC_SHA),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
			CipherSuite(TLS_DHE_RSA_WITH_AES_128_CCM_8),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256),
			CipherSuite(TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256),
			CipherSuite(TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256),
			CipherSuite(TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256),
			CipherSuite(TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256),
			CipherSuite(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256),
			CipherSuite(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA),
			CipherSuite(TLS_RSA_WITH_AES_256_GCM_SHA384),
			CipherSuite(TLS_RSA_WITH_AES_256_CCM),
			CipherSuite(TLS_RSA_WITH_AES_256_CBC_SHA256),
			CipherSuite(TLS_RSA_WITH_AES_256_CBC_SHA),
			CipherSuite(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384),
			CipherSuite(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384),
			CipherSuite(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA),
			CipherSuite(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384),
			CipherSuite(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384),
			CipherSuite(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA),
			CipherSuite(TLS_RSA_WITH_AES_256_CCM_8),
			CipherSuite(TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384),
			CipherSuite(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256),
			CipherSuite(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA),
			CipherSuite(TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384),
			CipherSuite(TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384),
			CipherSuite(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384),
			CipherSuite(TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384),
			CipherSuite(TLS_RSA_WITH_AES_128_GCM_SHA256),
			CipherSuite(TLS_RSA_WITH_AES_128_CCM),
			CipherSuite(TLS_RSA_WITH_AES_128_CBC_SHA256),
			CipherSuite(TLS_RSA_WITH_AES_128_CBC_SHA),
			CipherSuite(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256),
			CipherSuite(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256),
			CipherSuite(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA),
			CipherSuite(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256),
			CipherSuite(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256),
			CipherSuite(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA),
			CipherSuite(TLS_RSA_WITH_AES_128_CCM_8),
			CipherSuite(TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256),
			CipherSuite(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256),
			CipherSuite(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA),
			CipherSuite(TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256),
			CipherSuite(TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256),
			CipherSuite(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256),
			CipherSuite(TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256),
			CipherSuite(TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
		},
		CompressionLength: 1,
		Compression: []CompressionMethod{
			0x00,
		},
		ExtensionsLength: 72,
		Extensions:       []byte{0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x03, 0x06, 0x01, 0x05, 0x03, 0x05, 0x01, 0x04, 0x03, 0x04, 0x01, 0x03, 0x03, 0x03, 0x01, 0x02, 0x03, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x18, 0x00, 0x16, 0x00, 0x19, 0x00, 0x1c, 0x00, 0x18, 0x00, 0x1b, 0x00, 0x17, 0x00, 0x1a, 0x00, 0x15, 0x00, 0x13, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x1e, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00},
	}
	handshake := &Handshake{
		MsgType: ClientHelloHandshakeType,
		Length:  0,
		Body:    clientHello,
	}
	tlsPlainText := &TLSPlaintext{
		Type: HandshakeContentType,
		Version: ProtocolVersion{
			Major: 0x03,
			Minor: 0x03,
		},
		Fragment: handshake.Encode(),
	}
	tlsPlainText.Length = uint16(len(tlsPlainText.Fragment))
	tlsPlainTextBytes := tlsPlainText.Encode()

	// tcp client
	// conn, err := net.Dial("tcp", "14.119.104.189:443")
	conn, err := net.Dial("tcp", "52.82.77.63:8883")
	if err != nil {
		t.Fatal("tcp client error", err)
	}
	defer conn.Close()
	_, err = conn.Write(tlsPlainTextBytes)
	if err != nil {
		t.Fatal("tcp client error", err)
	}
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			if err.Error() == "EOF" {
				t.Log("tcp client read EOF")
				return
			}
			t.Fatal("tcp client error", err)
		}
		t.Log(buf[:n])
	}
}
