package webpushencrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
)

// Encrypt is encryption info.
type Encrypt struct {
	Payload    []byte
	Salt       []byte
	PublickKey []byte
}

func createServerKey() ([]byte, *big.Int, *big.Int, error) {
	salt, _ := createSalt(32)
	p, x, y, err := elliptic.GenerateKey(elliptic.P256(), bytes.NewReader(salt))
	if err != nil {
		return nil, nil, nil, err
	}
	return p, x, y, nil
}

func hkdf(salt, ikm, info []byte, l int) ([]byte, error) {
	if l > 32 {
		return nil, errors.New("length is less than 32")
	}

	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	hu := h.Sum(nil)

	i := hmac.New(sha256.New, hu)
	i.Write(info)
	i.Write([]byte{1})
	return i.Sum(nil)[0:l], nil
}

func createInfo(ty string, ctx []byte) []byte {
	w := bytes.NewBuffer([]byte{})
	w.WriteString("Content-Encoding: ")
	w.WriteString(ty)
	w.WriteByte(0)
	w.WriteString("P-256")
	w.Write(ctx)
	return w.Bytes()
}

func createSalt(i int) ([]byte, error) {
	b := make([]byte, i)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func createContext(cl, sv []byte) []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.WriteByte(0)
	bc := make([]byte, 2)
	binary.BigEndian.PutUint16(bc, uint16(len(cl)))
	buf.Write(bc)
	buf.Write(cl)
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(len(sv)))
	buf.Write(bs)
	buf.Write(sv)
	return buf.Bytes()
}

// GetEncryptoMessage returns encrypted messsage for web push api.
func GetEncryptoMessage(cl, auth string, raw []byte) (*Encrypt, error) {
	dc, err := base64.URLEncoding.DecodeString(cl)
	if err != nil {
		return nil, err
	}

	da, err := base64.URLEncoding.DecodeString(auth)
	if err != nil {
		return nil, err
	}

	salt, _ := createSalt(16)

	priv, x, y, err := createServerKey()
	if err != nil {
		return nil, err
	}
	pub := elliptic.Marshal(elliptic.P256(), x, y)

	px, py := elliptic.Unmarshal(elliptic.P256(), dc)
	ix, _ := elliptic.P256().ScalarMult(px, py, priv)

	b := bytes.NewBufferString("Content-Encoding: auth")
	b.WriteByte(0)

	prk, err := hkdf(da, ix.Bytes(), b.Bytes(), 32)
	if err != nil {
		return nil, err
	}

	ctx := createContext(dc, pub)

	ci := createInfo("aesgcm", ctx)
	ck, err := hkdf(salt, prk, ci, 16)
	if err != nil {
		return nil, err
	}

	ni := createInfo("nonce", ctx)
	n, err := hkdf(salt, prk, ni, 12)
	if err != nil {
		return nil, err
	}

	bl, err := aes.NewCipher(ck)
	if err != nil {
		return nil, err
	}

	cp, err := cipher.NewGCM(bl)
	if err != nil {
		return nil, err
	}

	buf := makePadding(0)
	buf.Write(raw)
	result := cp.Seal([]byte{}, n, buf.Bytes(), nil)
	printAll(priv, pub, salt)
	printAll(ix.Bytes(), prk, ci, ck, ni, n, result)
	return &Encrypt{
		Payload:    result,
		Salt:       salt,
		PublickKey: pub,
	}, nil
}

func convertBase64(b []byte) string {
	s := base64.URLEncoding.EncodeToString(b)
	s = strings.Replace(s, "+", "-", -1)
	s = strings.Replace(s, "/", "_", -1)
	s = strings.Replace(s, "=", "", -1)
	return s
}

func makePadding(l int) *bytes.Buffer {
	be := make([]byte, 2)
	binary.BigEndian.PutUint16(be, uint16(l))
	buf := bytes.NewBuffer(be)
	for i := 0; i < l; i++ {
		buf.WriteByte(0)
	}
	return buf
}

func printAll(b ...[]byte) {
	for _, v := range b {
		fmt.Println(convertBase64(v))
	}
}
