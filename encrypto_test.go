package webpushencrypto

import "testing"

func TestGetEncryptoMessage(t *testing.T) {
	b64k := "BClJhggKh-J5TiGi05P926XK5r7XdKOGHQTxnMx53_raRUpgrFBcUPVCWdBOrW8ofJjZfpG2bjgYsSacJiIjee4="
	b64a := "KvVpa60hivfIjBEq1I76zA=="
	res, err := GetEncryptoMessage(b64k, b64a, []byte("Hello, world!"))
	if err != nil {
		t.Fatal(err)
	}

	if res == nil {
		t.Fatal("result is empty")
	}
	t.Log(res.Payload)
}
