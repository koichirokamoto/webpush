package webpushencrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"strings"
)

func createServerKey(clientKey string) (ecdsa.PublicKey, error) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader(clientKey))
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	return p.PublicKey, nil
}

func hkdf(salt, ikm, info []byte, l int) ([]byte, error) {
	if l > 32 {
		return nil, errors.New("length is less than 32")
	}

	h := hmac.New(sha256.New, salt)
	hu := h.Sum(ikm)

	i := hmac.New(sha256.New, hu)
	iu := i.Sum([]byte{1})
	return iu[0 : l], nil
}

func createInfo(ty, cl, sv string) []byte {
	l := len([]byte(ty))
	i := make([]byte, 18+l+1+5+1+2+65+2+65)
	w := bytes.NewBuffer(i)
	w.WriteString("'Content-Encoding: '")
	w.WriteString(ty)
	w.Write(nil)
	w.WriteString("'P-256'")
	w.Write(nil)
	bc := make([]byte, 2)
	binary.BigEndian.PutUint16(bc, uint16(len(cl)))
	w.Write(bc)
	w.WriteString(cl)
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(len(sv)))
	w.Write(bs)
	w.WriteString(sv)
	return w.Bytes()
}

func createSalt() ([]byte, error) {
	c := 16
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GetEncryptoMessage returns encrypted messsage for web push api.
func GetEncryptoMessage(cl, auth, sv string, raw []byte) ([]byte, error) {
	svkey, err := createServerKey(cl)
	if err != nil {
		return nil, err
	}
	b := bytes.NewBuffer([]byte("'Content-Encoding: auth"))
	b.Write(nil)
	b.WriteString("'")
	ikm := elliptic.Marshal(svkey.Curve, svkey.X, svkey.Y)
	prk, err := hkdf([]byte(auth), ikm, b.Bytes(), 32)
	if err != nil {
		return nil, err
	}
	info := createInfo("aesgcm", cl, sv)
	salt, err := createSalt()
	if err != nil {
		return nil, err
	}
	key, err := hkdf(salt, prk, info, 16)
	if err != nil {
		return nil, err
	}

	ni := createInfo("nonce", cl, sv)
	n, err := hkdf(salt, prk, ni, 12)
	if err != nil {
		return nil, err
	}

	pad := make([]byte, 2)
	buf := bytes.NewBuffer(pad)
	buf.WriteByte(0)
	buf.WriteByte(0)
	bl, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cp, err := cipher.NewGCM(bl)
	if err != nil {
		return nil, err
	}

	var result []byte
	_ = cp.Seal(result, n, raw, buf.Bytes())
	return result, nil
}
