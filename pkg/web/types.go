package web

import (
	"crypto/rsa"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"net/url"
	"time"
)



type HandlerFunc func(http.ResponseWriter, *http.Request)
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}


type StateCookieConfig struct {
	Name   string
	EncKey []byte
}

type OauthFlowConfig struct {
	Oauth2            *oauth2.Config
	ClientCallbackUrl *url.URL
	MaxLoginWindow    time.Duration
}


type SigningFlowConfig struct{
	SigningAlgorithm  jose.SignatureAlgorithm
	PrivateKey 	*rsa.PrivateKey
	KeyId	string
	Audience string
	Issuer string
}

type surrogateJwtClaims struct {
	*jwt.Claims
	Email string   	`json:"email,omitempty"`
	Name string   	`json:"name,omitempty"`
}


type identityClaims struct {
	*jwt.Claims
	Upn string 	`json:"upn,omitempty"`
	Email string 	`json:"email,omitempty"`
	Name string 	`json:"name,omitempty"`
}