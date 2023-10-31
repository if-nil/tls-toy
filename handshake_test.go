package tls_toy

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"log"
	rand2 "math/rand"
	"net"
	"os"
	"testing"
	"time"
)

// var (
// 	clientHelloBuf = []byte{0x01, 0x00, 0x01, 0x0a, 0x03, 0x03, 0x6c, 0x20, 0x01, 0x04, 0x74, 0x74, 0xeb, 0x66, 0x55, 0xe1, 0xa3, 0x20, 0x85, 0x34, 0x62, 0x35, 0x37, 0xb9, 0xe5, 0x06, 0x76, 0xf7, 0x3b, 0xaa, 0xd5, 0xe7, 0xb5, 0xbf, 0x2e, 0xf1, 0xdc, 0xe9, 0x20, 0xe1, 0xee, 0xc7, 0xe9, 0xc3, 0x7d, 0x6c, 0x55, 0x39, 0xb9, 0x89, 0x04, 0x55, 0xcc, 0xff, 0x80, 0x75, 0xa9, 0x01, 0xf6, 0xc1, 0x8d, 0xf6, 0xf8, 0x39, 0x77, 0x1b, 0x74, 0x00, 0x77, 0x85, 0x86, 0x00, 0x26, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0x9b, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x1a, 0x00, 0x18, 0x08, 0x04, 0x04, 0x03, 0x08, 0x07, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x05, 0x03, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x12, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x34, 0xea, 0x52, 0x2a, 0xe2, 0x7d, 0x88, 0x66, 0x03, 0xf8, 0x67, 0xa5, 0x0d, 0x99, 0x62, 0x92, 0x13, 0x75, 0xf9, 0x8d, 0x6d, 0x18, 0xb1, 0x43, 0x33, 0xd2, 0x49, 0x4d, 0x83, 0x00, 0x2f, 0x37}
// 	gHandshake     = &Handshake{}
// )
//
// func init() {
// 	gHandshake.Body = &ClientHello{}
// 	gHandshake.Decode(clientHelloBuf[:])
// }

func TestClientHello(t *testing.T) {
	filePath := "D://tmp/sslkeylog.log"
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("文件打开失败", err)
	}
	// 及时关闭file句柄
	defer file.Close()

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

	finishedHash := crypto.SHA256.New()

	// clientHello ------------
	var randByte [28]byte
	rand2.Seed(time.Now().UnixNano())
	for i := 0; i < 28; i++ {
		randByte[i] = byte(rand2.Intn(256))
	}
	clientHello := &ClientHello{
		ClientVersion: ProtocolVersion{0x03, 0x03},
		Random: Random{
			GMTUnixTime: 0x649ebde5,
			// RandomBytes: [28]byte{0x81, 0xf1, 0x6d, 0x49, 0x06, 0xae, 0x05, 0x13, 0x36, 0x96, 0xaa, 0xfc, 0xb7, 0x8e, 0xe7, 0x68, 0x4e, 0x3d, 0x0a, 0x4b, 0xff, 0xbf, 0xad, 0x0e, 0x8a, 0x9b, 0xf4, 0xaf},
			RandomBytes: randByte,
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
		Extensions: []byte{0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x03, 0x06,
			0x01, 0x05, 0x03, 0x05, 0x01, 0x04, 0x03, 0x04, 0x01, 0x03, 0x03, 0x03,
			0x01, 0x02, 0x03, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x18, 0x00, 0x16, 0x00,
			0x19, 0x00, 0x1c, 0x00, 0x18, 0x00, 0x1b, 0x00, 0x17, 0x00, 0x1a, 0x00,
			0x15, 0x00, 0x13, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x1e, 0x00, 0x0b, 0x00,
			0x02, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
			0x23, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01},
		// ExtensionsLength: gHandshake.Body.(*ClientHello).ExtensionsLength,
		// Extensions:       gHandshake.Body.(*ClientHello).Extensions,
	}
	clientHello.ExtensionsLength = uint16(len(clientHello.Extensions))
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
	finishedHash.Write(tlsPlainText.Fragment)
	_, err = conn.Write(tlsPlainTextBytes)
	if err != nil {
		t.Fatal("tcp client error", err)
	}
	file.Write([]byte("CLIENT_RANDOM " + clientHello.Random.String() + " "))

	// serverHello ------------
	buf := <-buffChan
	tlsPlainText.Decode(buf)
	finishedHash.Write(tlsPlainText.Fragment)
	handshake.Body = &HelloRequest{}
	handshake.Decode(tlsPlainText.Fragment)
	serverHello := handshake.Body.(*HelloRequest)
	fmt.Printf("%+v\n", serverHello)

	// certificate ------------
	buf = buf[tlsPlainText.Length+5:]
	tlsPlainText.Decode(buf)
	finishedHash.Write(tlsPlainText.Fragment)
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
	finishedHash.Write(tlsPlainText.Fragment)
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
	finishedHash.Write(tlsPlainText.Fragment)
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
	finishedHash.Write(tlsPlainText.Fragment)

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
	sendbuff := append(tlsPlainTextBytes, tlsPlainText.Encode()...)
	// _, err = conn.Write(sendbuff)
	// if err != nil {
	// 	t.Fatal("tcp client error", err)
	// }
	// sendbuff = []byte{}

	// masterSecret ------------
	seed := make([]byte, 0, len(clientHello.Random.Encode())+len(serverHello.Random.Encode()))
	seed = append(seed, clientHello.Random.Encode()...)
	seed = append(seed, serverHello.Random.Encode()...)
	masterSecret := make([]byte, 48)
	prf12(sha256.New)(masterSecret, preMasterSecret, []byte("master secret"), seed)
	file.Write([]byte(hex.EncodeToString(masterSecret) + "\n"))

	// finished ------------
	verifyData := make([]byte, 12)
	prf12(sha256.New)(verifyData, masterSecret, []byte("client finished"), finishedHash.Sum(nil))
	var b cryptobyte.Builder
	b.AddUint8(uint8(FinishedHandshakeType))
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(verifyData)
	})
	data := b.BytesOrPanic()
	seed = make([]byte, 0, len(clientHello.Random.Encode())+len(serverHello.Random.Encode()))
	seed = append(seed, serverHello.Random.Encode()...)
	seed = append(seed, clientHello.Random.Encode()...)
	keyMaterial := make([]byte, 40)
	prf12(sha256.New)(keyMaterial, masterSecret, []byte("key expansion"), seed)
	clientKey := keyMaterial[:16]
	noncePrefix := keyMaterial[16*2 : 16*2+4]
	serverKey := keyMaterial[16 : 16*2]
	serverNoncePrefix := keyMaterial[16*2+4 : 16*2+4+4]
	aes1, err := aes.NewCipher(clientKey)
	if err != nil {
		t.Fatal("new cipher error", err)
	}
	record := make([]byte, 13)
	aead, err := cipher.NewGCM(aes1)
	if err != nil {
		t.Fatal("new gcm error", err)
	}
	serverAes, err := aes.NewCipher(serverKey)
	if err != nil {
		t.Fatal("new cipher error", err)
	}
	serverAead, err := cipher.NewGCM(serverAes)
	if err != nil {
		t.Fatal("new gcm error", err)
	}
	nonce := make([]byte, 12)
	copy(nonce, noncePrefix)
	tlsPlainText.Type = HandshakeContentType

	tlsPlainText.Fragment = nil
	tlsPlainText.Length = 16
	tlsPlainTextBytes = tlsPlainText.Encode()
	copy(record, tlsPlainTextBytes)
	record = aead.Seal(record, nonce, data, append(make([]byte, 8), tlsPlainTextBytes...))

	n := len(record) - 5
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	sendbuff = append(sendbuff, record...)
	_, err = conn.Write(sendbuff)

	// new session ticket ------------
	buf = <-buffChan
	tlsPlainText.Decode(buf)

	// changeCipherSpec ------------
	buf = buf[tlsPlainText.Length+5:]
	tlsPlainText.Decode(buf)

	// finished ------------
	buf = buf[tlsPlainText.Length+5:]
	tlsPlainText.Decode(buf)
	nonce1 := tlsPlainText.Fragment[:8]
	serverNonce := make([]byte, 12)
	copy(serverNonce, serverNoncePrefix)
	copy(serverNonce[4:], nonce1)
	tlsPlainText.Fragment = tlsPlainText.Fragment[8:]
	var additionalData []byte
	var scratchBuf [13]byte
	additionalData = append(scratchBuf[:0], make([]byte, 8)...)
	additionalData = append(additionalData, buf[:3]...)
	n = len(tlsPlainText.Fragment) - serverAead.Overhead()
	additionalData = append(additionalData, byte(n>>8), byte(n))
	plaintext, err := serverAead.Open(tlsPlainText.Fragment[:0], serverNonce, tlsPlainText.Fragment, additionalData)
	if err != nil {
		t.Fatal("open error", err)
	}
	_ = plaintext

	// application data ------------
	httpText := "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nUser-Agent: curl/8.0.1Accept: */*\r\n\r\n"
	tlsPlainText.Type = ApplicationDataContentType
	tlsPlainText.Fragment = []byte(httpText)
	tlsPlainText.Length = uint16(len(tlsPlainText.Fragment))
	tlsPlainTextBytes = tlsPlainText.Encode()
	record = make([]byte, 13)
	copy(record, tlsPlainTextBytes[:5])
	record[12] = 1
	nonce[11] = 1
	record = aead.Seal(record, nonce, tlsPlainText.Fragment, append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, tlsPlainTextBytes[:5]...))
	n = len(record) - 5
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	_, err = conn.Write(record)

	// recv application data ------------
	buf = <-buffChan
	tlsPlainText.Decode(buf)
	nonce1 = tlsPlainText.Fragment[:8]
	serverNonce = make([]byte, 12)
	copy(serverNonce, serverNoncePrefix)
	copy(serverNonce[4:], nonce1)
	tlsPlainText.Fragment = tlsPlainText.Fragment[8:]
	additionalData = []byte{}
	scratchBuf = [13]byte{}
	additionalData = append(scratchBuf[:0], []byte{0, 0, 0, 0, 0, 0, 0, 1}...)
	additionalData = append(additionalData, buf[:3]...)
	n = len(tlsPlainText.Fragment) - serverAead.Overhead()
	additionalData = append(additionalData, byte(n>>8), byte(n))
	plaintext, err = serverAead.Open(tlsPlainText.Fragment[:0], serverNonce, tlsPlainText.Fragment, additionalData)
	if err != nil {
		t.Fatal("open error", err)
	}
	fmt.Print(string(plaintext))

	select {}
}
