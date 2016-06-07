package webpushencrypto

import "testing"

func TestCreateSalt(t *testing.T) {
	_, err := createSalt()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateInfo(t *testing.T) {
	_ = createInfo("aesgcm", "clinetpublickey", "serverpublickey")
}

func TestHkdf(t *testing.T) {
	salt, _ := createSalt()
	ikm := []byte{1, 2, 3, 4, 5, 6}
	info := []byte{7, 8, 9}
	_, err := hkdf(salt, ikm, info, 32)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateServerKey(t *testing.T) {
	_, err := createServerKey("NSeFRZehVM:APA91bEDKm9dC-1T2B7TKExAVGDAXRJqgCQncrxCUc4SfbXUrClZxk8HmOuB3eC17UTb8oge6Fnuq86CrCpSLRjKg56kOFgqhiFVwNp3_lHQOi2-zOgn6GWM_1vD-5OrPh9QAQAd2KnX")
	if err != nil {
		t.Fatal(err)
	}
}
