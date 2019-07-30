package web

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/xynova/nakedjwts/pkg/cookies"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)





type SigningFlowConfig struct{
	SigningAlgorithm jose.SignatureAlgorithm
	PrivateKey       *rsa.PrivateKey
	KeyId            string
	Audiences        []string
	Issuer           *url.URL
	ConfigDir        string
	StateCookie      *cookies.Encrypted

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
			writeErrorResponseOut(w,"Cannot decode cookie", err, http.StatusUnauthorized )
			return
		}

		log.Debugf("accessToken from cookie: %s", accessToken)


		expires, err := BeginningOfMonth("Australia/Sydney")
		expires = time.Date(expires.Year(), expires.Month() + 1 , expires.Day(), 0,0,0,0, expires.Location())
		if err != nil {
			writeErrorResponseOut(w, "Failed to parse timezone", err, http.StatusInternalServerError)
			return
		}

		claims, err := parseIdentityClaimsFromToken(accessToken)
		if err != nil {
			writeErrorResponseOut(w, "Failed to get claims", err, http.StatusInternalServerError)
			return
		}
		log.Debugf("Parent decoded claims", claims)


		surrogateToken, err := createSurrogateToken(f,claims,expires)
		if err != nil {
			writeErrorResponseOut(w, "Failed to create JWT", err, http.StatusInternalServerError)
			return
		}

		pageData := pageData{
			AccessToken: accessToken,
			SurrogateToken:surrogateToken,
			SurrogateExpires: expires,
			EmailClaim: claims.Email,
			NameClaim: claims.Name,
		}
		templatePath := path.Join(f.ConfigDir,"display-token.html")
		log.Debugf("Template path", templatePath)
		err = writeTemplateOut(templatePath, pageData, w)
		if err != nil {
			writeErrorResponseOut(w,"Failed to render template",err,http.StatusInternalServerError)
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
			writeErrorResponseOut(w, "Failed to marshal KeySet", err, http.StatusInternalServerError)
			return
		}

		writeJsonOut(w, rt)
	}
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
