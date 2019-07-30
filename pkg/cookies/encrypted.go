package cookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"
)

var (
	encKey = []byte("a very very very very secret key") // 32 bytes
	CookieNotFoundError = errors.New("Cookie not found present")
)


type Encrypted struct {
	Name   	string
	Key		*rsa.PrivateKey
	Path 	string
}



func (c *Encrypted) SetValue(value string, expires time.Time, domain string, w http.ResponseWriter) error {

	cypherBytes, err := encryptBytes(encKey, []byte (value))
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name: c.Name,
		Value: base64.RawURLEncoding.EncodeToString(cypherBytes),
		Domain: domain,
		Expires: expires,
		Path: c.Path,
	}

	http.SetCookie(w, &cookie)
	return nil
}


func (c *Encrypted) GetValue(r *http.Request) (string,error) {

	cookie,err := r.Cookie(c.Name)
	if err != nil {
		return "", CookieNotFoundError
	}

	decodedValue, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := decryptBytes(encKey,decodedValue )
	if err != nil {
		return "", err
	}

	return string(decryptedBytes),nil
}




func encryptBytes(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}



func decryptBytes(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
