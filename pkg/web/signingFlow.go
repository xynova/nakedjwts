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


// Creates a Surrogate token from parameters
func (f *SigningFlowConfig) IssueSurrogateToken( expires time.Time, name, email, subject string) (string, error){
	key := jose.SigningKey{Algorithm: f.SigningAlgorithm, Key: f.PrivateKey}
	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid" , f.KeyId)
	signerOpts.WithHeader("x5t", "TODO: set md5 of the key")

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return "", errorFrom(err,"Failed to create signer" )
	}

	customClaims := &SurrogateJwtClaims{
		Claims: &jwt.Claims{
			//ID:       "id1",
			Issuer:   strings.TrimSuffix(f.Issuer.String(),"/") + "/",
			Audience: jwt.Audience(f.Audiences),
			Subject:  subject,
			IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
			Expiry: jwt.NewNumericDate(expires),
		},
		Email: email,
		Name: name,
	}

	rt, err := jwt.Signed(rsaSigner).Claims(customClaims).CompactSerialize()
	if err != nil {
		return "", errorFrom(err, "Failed to create JWT")
	}

	return rt, nil
}


// Renders a Surrogate token from data stored within an http cookie
func (f *SigningFlowConfig) RenderSurrogateJwtHandle(expiryCalculator func()(time.Time, error)) http.HandlerFunc {

	return func (w http.ResponseWriter, r *http.Request) {


		// Get identity token stored in a web cookie
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

		claims, err := parseIdentityClaimsFromToken(accessToken)
		if err != nil {
			writeErrorResponseOut(w, "Failed to get claims", err, http.StatusInternalServerError)
			return
		}
		log.Debugf("Parent decoded claims", claims)


		// Create surrogate token
		expires, err := expiryCalculator()
		if err != nil {
			writeErrorResponseOut(w, "Failed to parse timezone", err, http.StatusInternalServerError)
			return
		}

		surrogateToken, err := f.IssueSurrogateToken(expires,claims.Name,claims.Email,claims.Subject)
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




// Renders the public key to validate the issued surrogate token
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

