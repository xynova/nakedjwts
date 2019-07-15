package main

import (
	"encoding/base64"
	"fmt"
	"github.com/Masterminds/sprig"
	"golang.org/x/oauth2"
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
	cypherBytes, err := encrypt(s.stateKey, []byte (oauthState))
	if err != nil {
		log.Fatal(err)
	}

	expire := time.Now().Add(s.loginWindow)
	cookie := http.Cookie{
		Name:"baggage",
		Value: base64.StdEncoding.EncodeToString(cypherBytes),
		Domain: r.Host,
		Expires: expire,
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w,r, loginUrl,http.StatusTemporaryRedirect)
}


func (s *serviceConfig) renderToken(w http.ResponseWriter, r *http.Request) {
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

	oauthStateBytes, err := decrypt(s.stateKey,decodedValue )
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
		writeHtmlErrorResponse(w,err)
		return
	}
	log.Debugf("TEMPLATES:>  %s", tmpl.DefinedTemplates())
	pageData := PageData{
		AccessToken: token.AccessToken,
	}

	if err := tmpl.Execute(w, pageData); err != nil {
		writeHtmlErrorResponse(w,err)
		return
	}

}

func writeHtmlErrorResponse(w http.ResponseWriter, e error ){
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(e.Error()))
	return
}

