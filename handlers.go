package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/sprig"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"os"
	"path"
	"time"
	log "github.com/sirupsen/logrus"
	"context"
	"html/template"
)



type PageData struct {
	AccessToken string
}



func (s *serviceConfig) rootHandler(w http.ResponseWriter, r *http.Request) {
	oauthState := randString()
	log.Debugf("oauthState: %s", oauthState)
	loginUrl := s.oauth2.AuthCodeURL(oauthState, oauth2.AccessTypeOnline)
	cypherBytes, err := encrypt(s.stateEncKey, []byte (oauthState))
	if err != nil {
		log.Fatal(err)
	}

	expire := time.Now().Add(s.maxLoginWindow)
	cookie := http.Cookie{
		Name:"baggage",
		Value: base64.StdEncoding.EncodeToString(cypherBytes),
		Domain: r.Host,
		Expires: expire,
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w,r, loginUrl,http.StatusTemporaryRedirect)
}


func (s *serviceConfig) renderTokenHandler(w http.ResponseWriter, r *http.Request) {
	//defer wg.Done()

	cookie,err := r.Cookie("baggage")
	if err != nil {
		http.Error(w, fmt.Sprintf("%s", err), http.StatusBadRequest)
		return
	}

	decodedValue, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot decode baggage %s",cookie.Value), http.StatusUnauthorized)
		return
	}

	oauthStateBytes, err := decrypt(s.stateEncKey,decodedValue )
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot decrypt baggage"), http.StatusUnauthorized)
		return
	}

	oauthState := string(oauthStateBytes)
	log.Debugf("oauthState: %s", oauthState)


	if s := r.URL.Query().Get("state"); s != oauthState {
		http.Error(w, fmt.Sprintf("Invalid oauthState: %s", s), http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")
	ctx := context.Background()
	token, err := s.oauth2.Exchange(ctx, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Exchange error: %s", err), http.StatusServiceUnavailable)
		return
	}


	//tokenJSON, err := json.MarshalIndent(token, "", "  ")
	//if err != nil {
	//	http.Error(w, fmt.Sprintf("Token parse error: %s", err), http.StatusServiceUnavailable)
	//	return
	//}


	var tmpl *template.Template


	//t := template.New("base").Funcs(sprig.FuncMap()).ParseFiles("template.html")
	templateName := "template.html"
	configDir, _ := os.Getwd()

	var tmplPath = path.Join(configDir,templateName)
	if tmpl, err = template.New(templateName).Funcs(sprig.FuncMap()).ParseFiles(tmplPath); err != nil {
		writeErrorResponse(w,err,http.StatusInternalServerError)
		return
	}
	log.Debugf("TEMPLATES:>  %s", tmpl.DefinedTemplates())
	pageData := PageData{
		AccessToken: token.AccessToken,
	}

	if err := tmpl.Execute(w, pageData); err != nil {
		writeErrorResponse(w,err,http.StatusInternalServerError)
		return
	}

}



func (s *serviceConfig) jwksHandler(w http.ResponseWriter, r *http.Request) {
	pub := jose.JSONWebKey{
		Key: s.pubKey,
		Use: "sig",
		Algorithm: "RS256",
		KeyID: "default",
	}

	keyset := &jose.JSONWebKeySet{ Keys: []jose.JSONWebKey{ pub } }
	rt, err := json.Marshal(keyset)
	if err != nil {
		writeErrorResponse(w,err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.Write(rt)
}



func (s * serviceConfig) jwtTokenHandler(w http.ResponseWriter, r *http.Request) {
	// create Square.jose signing key
	key := jose.SigningKey{Algorithm: jose.RS256, Key: s.privKey}

	// create a Square.jose RSA signer, used to sign the JWT
	var signerOpts= jose.SignerOptions{}
	signerOpts.WithType("JWT")
	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		log.Fatalf("failed to create signer:%+v", err)
	}

	// create an instance of Builder that uses the rsa signer
	builder := jwt.Signed(rsaSigner)


	// create an instance of the CustomClaim
	customClaims := CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   "http://192.168.1.11:5000/",
			Subject:  "hector.maldonado@subabank.com",
			ID:       "id1",
			Audience: jwt.Audience{r.Host},
			IssuedAt:
			jwt.NewNumericDate(time.Now().UTC()),
			Expiry:
			jwt.NewNumericDate(time.Date(2019, 8, 1, 0, 8, 0, 0, time.UTC)),
		},
		PrivateClaim1: "val1",
		PrivateClaim2: []string{"val2", "val3"},
		AnyJSONObjectClaim: map[string]interface{}{
			"name": "john",
			"phones": map[string]string{
				"phone1": "123",
				"phone2": "456",
			},
		},
	}
	// add claims to the Builder
	builder = builder.Claims(customClaims)

	// validate all ok, sign with the RSA key, and return a compact JWT
	rt, err := builder.CompactSerialize()
	if err != nil {
		log.Fatalf("failed to create JWT:%+v", err)
	}

	w.Header().Set("Content-Type", "text/json")
	w.Write([]byte(rt))
}


type CustomClaims struct {
	*jwt.Claims
	PrivateClaim1 string   `json:"privateClaim1,omitempty"`
	PrivateClaim2 []string `json:"privateClaim2,omitEmpty"`
	AnyJSONObjectClaim map[string]interface{} `json:"anyJSONObjectClaim"`
}
