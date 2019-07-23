package web

import (
	"context"
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/xynova/nakedjwts/pkg/cookies"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"time"
)


type OauthFlowConfig struct {
	Oauth2            *oauth2.Config
	ClientCallbackUrl *url.URL
	MaxLoginWindow    time.Duration
	StateCookie       *cookies.EncryptedSetter
}


func (f *OauthFlowConfig) LoginInitHandle() http.HandlerFunc{
	return func (w http.ResponseWriter, r *http.Request) {
		log.Debugf("currentPath:" ,r.URL)

		oauthState := randString()
		log.Debugf("oauthState: %s", oauthState)
		loginUrl := f.Oauth2.AuthCodeURL(oauthState, oauth2.AccessTypeOnline)

		err := f.StateCookie.SetValue(oauthState, time.Now().Add(f.MaxLoginWindow), r.Host, w)
		if err != nil {
			writeErrorResponse(w,"Error writing the cookie", err, http.StatusInternalServerError )
			return
		}
		http.Redirect(w,r, loginUrl,http.StatusTemporaryRedirect)
	}
}


func (f *OauthFlowConfig) LoginCallbackHandle(  next http.HandlerFunc) http.HandlerFunc{

	return func (w http.ResponseWriter, r *http.Request) {

		oauthState,err := f.StateCookie.GetValue(r)
		if err == cookies.CookieNotFoundError {
			log.Debug("Cookie for state not present")
			http.Redirect(w, r, f.StateCookie.Path,http.StatusTemporaryRedirect)
			return
		}

		if err != nil {
			writeErrorResponse(w,"Cannot decode cookie", err, http.StatusUnauthorized )
			return
		}

		log.Debugf("Login oauthState: %s", oauthState)
		if s := r.URL.Query().Get("state"); s != oauthState {
			writeErrorResponse(w,"Invalid oauthState", errors.New(s), http.StatusUnauthorized )
			return
		}


		code := r.URL.Query().Get("code")
		ctx := context.Background()
		token, err := f.Oauth2.Exchange(ctx, code)
		if err != nil {
			writeErrorResponse(w,"Auth token exchange error", err, http.StatusServiceUnavailable )
			return
		}

		// We should be authenticated here so set session
		log.Debug("Got identity token from login: %s" , token)
		err = f.StateCookie.SetValue(token.AccessToken, time.Now().Add(2 * time.Second) , r.Host, w )
		if err != nil {
			writeErrorResponse(w,"Failed to set cookie",err,http.StatusInternalServerError)
			return
		}


		next(w, r)
	}
}

