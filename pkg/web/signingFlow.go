package web

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/Masterminds/sprig"
	log "github.com/sirupsen/logrus"
	"github.com/xynova/nakedjwts/pkg/cookies"
	"gopkg.in/square/go-jose.v2"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"time"
)





type SigningFlowConfig struct{
	SigningAlgorithm jose.SignatureAlgorithm
	PrivateKey       *rsa.PrivateKey
	KeyId            string
	Audiences        []string
	Issuer           *url.URL
	ConfigDir        string
	StateCookie      *cookies.EncryptedSetter

}




func (f *SigningFlowConfig) RenderSurrogateJwtHandle() http.HandlerFunc {

	return func (w http.ResponseWriter, r *http.Request) {


		accessToken,err := f.StateCookie.GetValue(r)

		if err == cookies.CookieNotFoundError {
			log.Debug("Cookie for identityToken not present")
			http.Redirect(w, r, f.StateCookie.Path,http.StatusTemporaryRedirect)
			return
		}

		if err != nil {
			writeErrorResponse(w,"Cannot decode cookie", err, http.StatusUnauthorized )
			return
		}

		log.Debugf("accessToken from cookie: %s", accessToken)


		expires, err := BeginningOfMonth("Australia/Sydney")
		expires = time.Date(expires.Year(), expires.Month() + 1 , expires.Day(), 0,0,0,0, expires.Location())
		if err != nil {
			writeErrorResponse(w, "Failed to parse timezone", err, http.StatusInternalServerError)
			return
		}

		claims, err := parseIdentityClaimsFromToken(accessToken)
		if err != nil {
			writeErrorResponse(w, "Failed to get claims", err, http.StatusInternalServerError)
			return
		}
		log.Debugf("Parent decoded claims", claims)

		surrogateToken, err := createSurrogateToken(f,claims,expires)
		if err != nil {
			writeErrorResponse(w, "Failed to create JWT", err, http.StatusInternalServerError)
			return
		}

		pageData := pageData{
			AccessToken: accessToken,
			SurrogateToken:surrogateToken,
			SurrogateExpires: expires,
		}


		var tmpl *template.Template


		//t := template.New("base").Funcs(sprig.FuncMap()).ParseFiles("display-token.html")
		templateName := "display-token.html"
		var tmplPath = path.Join(f.ConfigDir,templateName)
		if tmpl, err = template.New(templateName).Funcs(sprig.FuncMap()).ParseFiles(tmplPath); err != nil {
			writeErrorResponse(w, "Cannot parse template", err,http.StatusInternalServerError)
			return
		}
		log.Debugf("TEMPLATES:>  %s", tmpl.DefinedTemplates())


		if err := tmpl.Execute(w, pageData); err != nil {
			writeErrorResponse(w,"Failed to render template",err,http.StatusInternalServerError)
			return
		}

		err = f.StateCookie.SetValue("",time.Now() , r.Host, w )
		if  err != nil {
			writeErrorResponse(w,"Failed to set cookie",err,http.StatusInternalServerError)
			return
		}
	}
}





func (f *SigningFlowConfig) RenderJwksHandle() http.HandlerFunc{

	return func (w http.ResponseWriter, r *http.Request) {
		log.Debugf("currentPath:" ,r.URL)

		jswk := jose.JSONWebKey{
			Key:       f.PrivateKey.Public(),
			Use:       "sig",
			Algorithm: string(f.SigningAlgorithm),
			KeyID:     f.KeyId,
		}

		keySet := &jose.JSONWebKeySet{ Keys: []jose.JSONWebKey{ jswk } }
		rt, err := json.Marshal(keySet)
		if err != nil {
			writeErrorResponse(w, "Failed to marshal KeySet", err, http.StatusInternalServerError)
			return
		}

		writeJsonOut(w, rt)
	}
}
