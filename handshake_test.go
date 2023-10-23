package tls_toy

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"testing"
	"time"
)

func TestClientHello(t *testing.T) {

	buffChan := make(chan []byte)

	// tcp client
	conn, err := net.Dial("tcp", "14.119.104.189:443")
	// conn, err := net.Dial("tcp", "52.82.77.63:8883")
	if err != nil {
		t.Fatal("tcp client error", err)
	}
	defer conn.Close()
	go func() {
		for {
			buf := make([]byte, 10240)
			n, err := conn.Read(buf)
			if err != nil {
				if err.Error() == "EOF" {
					t.Log("tcp client read EOF")
					return
				}
				t.Fatal("tcp client error", err)
			}
			t.Log(buf[:n])
			bufCopy := make([]byte, n)
			copy(bufCopy, buf[:n])
			buffChan <- bufCopy
		}
	}()

	// clientHello ------------
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
	_, err = conn.Write(tlsPlainTextBytes)
	if err != nil {
		t.Fatal("tcp client error", err)
	}

	// serverHello ------------
	buf := <-buffChan
	tlsPlainText.Decode(buf)
	handshake.Body = &HelloRequest{}
	handshake.Decode(tlsPlainText.Fragment)
	serverHello := handshake.Body.(*HelloRequest)
	fmt.Printf("%+v\n", serverHello)

	// certificate ------------
	buf = buf[tlsPlainText.Length+5:]
	tlsPlainText.Decode(buf)
	handshake.Body = &Certificates{}
	handshake.Decode(tlsPlainText.Fragment)
	certificate := handshake.Body.(*Certificates)
	fmt.Printf("%+v\n", certificate)

	// verify certificate ------------
	certs := make([]*x509.Certificate, len(certificate.Certificates))
	for i, cert := range certificate.Certificates {
		cert, err := x509.ParseCertificate(cert.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		certs[i] = cert
	}
	opts := x509.VerifyOptions{
		Roots:         nil,
		CurrentTime:   time.Now(),
		DNSName:       "baidu.com",
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	verifiedChains, err := certs[0].Verify(opts)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n", verifiedChains)

	// serverKeyExchange ------------
	buf = buf[tlsPlainText.Length+5:]
	tlsPlainText.Decode(buf)
	handshake.Body = &ECServerParams{}
	handshake.Decode(tlsPlainText.Fragment)
	ecServerParams := handshake.Body.(*ECServerParams)
	fmt.Printf("%+v\n", ecServerParams)
	// // verify serverKeyExchange signature ------------
	h := crypto.SHA512.New()
	slices := [][]byte{
		clientHello.Random.Encode(),
		serverHello.Random.Encode(),
		ecServerParams.Raw,
	}
	for _, slice := range slices {
		h.Write(slice)
	}
	digest := h.Sum(nil)
	err = rsa.VerifyPKCS1v15(certs[0].PublicKey.(*rsa.PublicKey), crypto.SHA512, digest, ecServerParams.Sig)
	if err != nil {
		t.Fatal("verify serverKeyExchange error", err)
	}

	// serverHelloDone ------------
	buf = buf[tlsPlainText.Length+5:]
	tlsPlainText.Decode(buf)
	handshake.Body = &HelloRequest{}
	handshake.Decode(tlsPlainText.Fragment)
	serverHelloDone := handshake.Body.(*HelloRequest)
	fmt.Printf("%+v\n", serverHelloDone)

	// clientKeyExchange ------------
	curve := elliptic.P256()
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal("generate key error", err)
	}
	x1, y1 := elliptic.Unmarshal(curve, ecServerParams.Pubkey)
	if x1 == nil {
		t.Fatal("unmarshal pubkey failed")
	}
	xShared, _ := curve.ScalarMult(x1, y1, privateKey)
	sharedKey := make([]byte, (curve.Params().BitSize+7)/8)
	preMasterSecret := xShared.FillBytes(sharedKey)
	if preMasterSecret == nil {
		t.Fatal("failed to get preMasterSecret")
	}
	ourPublicKey := elliptic.Marshal(curve, x, y)

	cke := &ClientKeyExchange{}
	cke.Pubkey = ourPublicKey
	cke.PubkeyLen = uint8(len(cke.Pubkey))
	handshake = &Handshake{
		MsgType: ClientKeyExchangeHandshakeType,
		Length:  0,
		Body:    cke,
	}
	tlsPlainText.Fragment = handshake.Encode()
	tlsPlainText.Length = uint16(len(tlsPlainText.Fragment))
	tlsPlainTextBytes = tlsPlainText.Encode()

	// changeCipherSpec ------------
	ccs := ChangeCipherSpec(1)
	tlsPlainText = &TLSPlaintext{
		Type: ChangeCipherSpecContentType,
		Version: ProtocolVersion{
			Major: 0x03,
			Minor: 0x03,
		},
		Fragment: ccs.Encode(),
		Length:   1,
	}
	tlsPlainTextBytes = append(tlsPlainTextBytes, tlsPlainText.Encode()...)
	_, err = conn.Write(tlsPlainTextBytes)

	// finished ------------
	prf := func(result, secret, label, seed []byte) {
		pHash(result, secret, label, seed, sha256.New)
	}
	hash := crypto.SHA256.New()
	hash.Write(clientHello.Encode())

	finished := &Finished{}
	handshake = &Handshake{
		MsgType: FinishedHandshakeType,
		Length:  0,
		Body:    finished,
	}
	tlsPlainText.Fragment = handshake.Encode()
	tlsPlainText.Length = uint16(len(tlsPlainText.Fragment))
	// tlsPlainTextBytes = append(tlsPlainTextBytes, tlsPlainText.Encode()...)
	// _, err = conn.Write(tlsPlainTextBytes)
	_ = prf
	select {}
}
