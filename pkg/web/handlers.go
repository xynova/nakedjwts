package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Masterminds/sprig"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"html/template"
	"net/http"
	"path"
	"time"
)






func OauthLoginInitHandler(flowConfig *OauthFlowConfig ,cookieConfig *StateCookieConfig) http.HandlerFunc{
	return func (w http.ResponseWriter, r *http.Request) {
		oauthState := randString()
		log.Debugf("oauthState: %s", oauthState)
		loginUrl := flowConfig.Oauth2.AuthCodeURL(oauthState, oauth2.AccessTypeOnline)
		cypherBytes, err := encryptBytes(cookieConfig.EncKey, []byte (oauthState))
		if err != nil {
			log.Fatal(err)
		}

		expire := time.Now().Add(flowConfig.MaxLoginWindow)
		cookie := http.Cookie{
			Name: cookieConfig.Name,
			Value: base64.StdEncoding.EncodeToString(cypherBytes),
			Domain: r.Host,
			Expires: expire,
		}

		http.SetCookie(w, &cookie)
		http.Redirect(w,r, loginUrl,http.StatusTemporaryRedirect)
	}
}


func OauthLoginCallbackHandler(flowConfig *OauthFlowConfig, cookieConfig *StateCookieConfig, next http.HandlerFunc) http.HandlerFunc{

	return func (w http.ResponseWriter, r *http.Request) {
		cookie,err := r.Cookie(cookieConfig.Name)
		if err != nil {
			log.Debug("Cookie for state not present")
			http.Redirect(w, r, cookieConfig.Path,http.StatusTemporaryRedirect)
			return
		}

		decodedValue, err := base64.StdEncoding.DecodeString(cookie.Value)
		if err != nil {
			http.Error(w, fmt.Sprintf("Cannot decode baggage %s",cookie.Value), http.StatusUnauthorized)
			return
		}

		oauthStateBytes, err := decryptBytes(cookieConfig.EncKey,decodedValue )
		if err != nil {
			http.Error(w, fmt.Sprintf("Cannot decryptBytes baggage"), http.StatusUnauthorized)
			return
		}

		oauthState := string(oauthStateBytes)
		log.Debugf("Login oauthState: %s", oauthState)


		if s := r.URL.Query().Get("state"); s != oauthState {
			http.Error(w, fmt.Sprintf("Invalid oauthState: %s", s), http.StatusUnauthorized)
			return
		}



		code := r.URL.Query().Get("code")
		ctx := context.Background()
		token, err := flowConfig.Oauth2.Exchange(ctx, code)
		if err != nil {
			http.Error(w, fmt.Sprintf("Exchange error: %s", err), http.StatusServiceUnavailable)
			return
		}

		// We should be authenticated here so set session
		log.Debug("Got identity token from login: %s" , token)

		cypherBytes, err := encryptBytes(cookieConfig.EncKey, []byte (token.AccessToken))
		if err != nil {
			http.Error(w, fmt.Sprintf("Encryption error: %s", err), http.StatusInternalServerError)
			return
		}

		expire := time.Now().Add(2 * time.Second)
		oauthCookie := http.Cookie{
			Name: cookieConfig.Name,
			Value: base64.StdEncoding.EncodeToString(cypherBytes),
			Domain: r.Host,
			Expires: expire,
			Path: "/",
		}
		http.SetCookie(w, &oauthCookie)
		next(w, r)
	}
}




func RenderSurrogateJwtHandler(flowConfig *SigningFlowConfig,cookieConfig *StateCookieConfig) http.HandlerFunc {

	return func (w http.ResponseWriter, r *http.Request) {

		cookie,err := r.Cookie(cookieConfig.Name)
		if err != nil {
			log.Debug("Cookie for identityToken not present")
			http.Redirect(w, r, cookieConfig.Path,http.StatusTemporaryRedirect)
			return
		}

		log.Debugf("cookie value: %s", cookie.Value)
		decodedValue, err := base64.StdEncoding.DecodeString(cookie.Value)
		if err != nil {
			http.Error(w, fmt.Sprintf("Cannot decode baggage %s",cookie.Value), http.StatusUnauthorized)
			return
		}

		oauthStateBytes, err := decryptBytes(cookieConfig.EncKey, decodedValue )
		if err != nil {
			http.Error(w, fmt.Sprintf("Cannot decryptBytes baggage"), http.StatusUnauthorized)
			return
		}

		accessToken := string(oauthStateBytes)
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

		surrogateToken, err := createSurrogateToken(flowConfig,claims,expires)
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
		var tmplPath = path.Join(flowConfig.ConfigDir,templateName)
		if tmpl, err = template.New(templateName).Funcs(sprig.FuncMap()).ParseFiles(tmplPath); err != nil {
			writeErrorResponse(w, "Cannot parse template", err,http.StatusInternalServerError)
			return
		}
		log.Debugf("TEMPLATES:>  %s", tmpl.DefinedTemplates())


		if err := tmpl.Execute(w, pageData); err != nil {
			writeErrorResponse(w,"Failed to render template",err,http.StatusInternalServerError)
			return
		}

		expire := time.Now()
		oauthCookie := http.Cookie{
			Name: cookieConfig.Name,
			Domain: r.Host,
			Expires: expire,
			Path: "/",
		}
		http.SetCookie(w, &oauthCookie)

	}
}





func RenderJwksHandler(flowConfig *SigningFlowConfig) http.HandlerFunc{

	return func (w http.ResponseWriter, r *http.Request) {
		jswk := jose.JSONWebKey{
			Key: flowConfig.PrivateKey.Public(),
			Use: "sig",
			Algorithm: string(flowConfig.SigningAlgorithm),
			KeyID: flowConfig.KeyId,
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
