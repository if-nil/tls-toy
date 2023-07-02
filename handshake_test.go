package tls_toy

import (
	"crypto/rand"
	"testing"
)

func TestClientHello(t *testing.T) {
	clientHello := &ClientHello{
		ClientVersion: ProtocolVersion{0x03, 0x03},
		Random: Random{
			GMTUnixTime: 4259206282,
			RandomBytes: func() [28]byte {
				randomBytes := make([]byte, 28)
				rand.Read(randomBytes)
				var random [28]byte
				copy(random[:], randomBytes)
				return random
			}(),
		},
		SessionLength: 32,
		SessionID: func() []byte {
			sessionID := make([]byte, 32)
			rand.Read(sessionID)
			return sessionID
		}(),
		CipherSuitesLength: 4,
		CipherSuites: []CipherSuite{
			TLS_AES_256_GCM_SHA384,
			TLS_AES_128_GCM_SHA256,
		},
		CompressionLength: 1,
		Compression: []CompressionMethod{
			0x00,
		},
		ExtensionsLength: 0,
	}
	handshake := &Handshake{}
	_ = handshake
	_ = clientHello
}
