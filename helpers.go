package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	log "github.com/sirupsen/logrus"
)



func encrypt(key, text []byte) ([]byte, error) {
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



func decrypt(key, text []byte) ([]byte, error) {
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



func randString() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func getPrivateKey(path string) (crypto.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil ,err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}


	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return parsedKey, nil
}

func getPublicKey(path string) (crypto.PublicKey, error) {

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil ,err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch parsedKey.(type) {
	case *rsa.PublicKey:
		return parsedKey, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}


func writeErrorResponse(w http.ResponseWriter, e error, code int  ){
	log.Errorf("Cannot marshal Json %s", e)
	http.Error(w, fmt.Sprintf("%s",e), code)
}

