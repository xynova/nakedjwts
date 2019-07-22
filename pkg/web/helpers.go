package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)



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



func randString() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func ReadRsaPrivateKey(path string) (*rsa.PrivateKey, error) {
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
		switch err.(type) {
		case asn1.StructuralError:
			return nil, errors.New("The file doesnt seem to represent an RSA private key")
		default:
			return nil, err
		}
	}
	return parsedKey, nil
}



func writeErrorResponse(w http.ResponseWriter, message string, e error, code int  ){
	err := errorFrom(e, message)
	log.Errorf(err.Error())
	http.Error(w, err.Error(), code)
}

func errorFrom( e error, message string ) error{
	msg := fmt.Sprintf("%s: %+v", message, e)
	return errors.New(msg)
}

func writeJsonOut(w http.ResponseWriter, docBytes []byte){
	w.Header().Set("Content-Type", "application/json")
	w.Write(docBytes)
}


func createSurrogateToken(flowConfig *SigningFlowConfig, claims *identityClaims, expires time.Time) (string, error){
	key := jose.SigningKey{Algorithm: flowConfig.SigningAlgorithm, Key: flowConfig.PrivateKey}
	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid" , flowConfig.KeyId)
	signerOpts.WithHeader("x5t", "TODO: set md5 of the key")

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return "", errorFrom(err,"Failed to create signer" )
	}

	customClaims := surrogateJwtClaims{
		Claims: &jwt.Claims{
			//ID:       "id1",
			Issuer:   strings.TrimSuffix(flowConfig.Issuer.String(),"/") + "/",
			Audience: jwt.Audience(flowConfig.Audiences),
			Subject:  claims.Subject,
			IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
			Expiry: jwt.NewNumericDate(expires),
		},
		Email: claims.Email,
		Name: claims.Name,
	}


	rt, err := jwt.Signed(rsaSigner).Claims(customClaims).CompactSerialize()
	if err != nil {
		return "", errorFrom(err, "Failed to create JWT")
	}

	return rt, nil
}


func parseIdentityClaimsFromToken( jwtToken string) (*identityClaims, error){


	parts := strings.Split(jwtToken, ".")
	if len(parts) < 2 {
		return nil, errors.New("Invalid JWT token")
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errorFrom(err, "Failed to base64 decode JWT claims section")
	}

	claims := &identityClaims{}
	if json.Unmarshal(data, claims) != nil {
		return nil, errorFrom(err, "Failed to decode claims")
	}

	// Fix subject if it is an azure token
	if claims.Upn != "" {
		claims.Subject = claims.Upn
	}

	// Fix email if it is empty
	if claims.Email == "" && strings.Contains(claims.Subject, "@") {
		claims.Email = claims.Subject
	}

	return claims, nil
}


func BeginningOfMonth(tz string) (time.Time, error) {

	//y, m, _ := time.Now().Date()
	location, err:= time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, err
	}

	t := time.Now().In(location)

	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, location), nil
}
