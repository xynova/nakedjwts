package web

import (
	"gopkg.in/square/go-jose.v2/jwt"
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
