package web

import (
	"crypto/rsa"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/url"
	"time"
)


//
//type HandlerFunc func(http.ResponseWriter, *http.Request)
//func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
//	f(w, r)
//}


type StateCookieConfig struct {
	Name   string
	EncKey []byte
	Path 	string
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
	Audiences []string
	Issuer *url.URL
	ConfigDir string
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


type pageData struct {
	AccessToken string
	SurrogateToken string
	SurrogateExpires time.Time
}
