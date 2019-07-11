package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/Masterminds/sprig"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"html/template"
	"io"
	defaultLog "log"
	"net/http"
	"os"
	"path"
	"time"
)

type Scopes []string

func (s *Scopes) String() string {
	return fmt.Sprintf("%s", *s)
}

func (s *Scopes) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type PageData struct {
	AccessToken string
}

type serverJsonWriter struct {
	io.Writer
}

func (w serverJsonWriter) Write(p []byte) (n int, err error){
	// {"error":{"type":"net/http error","message":"header too long"}}
	log.Debug(string(p))
	return 0, nil
}


func randString() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	return base64.StdEncoding.EncodeToString(buf)
}

func main() {



	var (
		port         = flag.Int("port", 8080, "Callback port")
		callbackPath         = flag.String("callback-path", "/oauth2/callback", "Callback path")
		clientID     = flag.String("client-id", "", "Client ID")
		clientSecret = flag.String("client-secret", "", "Client secret")
		authURL      = flag.String("authorize-url", "https://localhost/oauth2/authorize", "Authorization URL")
		tokenURL     = flag.String("token-url", "https://localhost/oauth2/token", "Token URL")
		loginWindow  = flag.Duration("login-window", 30 * time.Second, "Max time allowed for login to happen. eg: 30s")
		debug 		 = flag.Bool("debug", false, "Turn verbose logs on")
		scopes       Scopes
	)
	flag.Var(&scopes, "scope", "oAuth scopes to authorize (can be specified multiple times")
	flag.Parse()

	// Set log level
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	config := &oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Scopes:       scopes,
		RedirectURL:  fmt.Sprintf("http://localhost:%d%s", *port, *callbackPath),
		Endpoint: oauth2.Endpoint{
			AuthURL:  *authURL,
			TokenURL: *tokenURL,
		},
	}

	ctx := context.Background()



	key := []byte("a very very very very secret key") // 32 bytes


	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		oauthState := randString()
		log.Debugf("oauthState: %s", oauthState)
		loginUrl := config.AuthCodeURL(oauthState, oauth2.AccessTypeOnline)
		cypherBytes, err := encrypt(key, []byte (oauthState))
		if err != nil {
			log.Fatal(err)
		}

		expire := time.Now().Add(*loginWindow)
		cookie := http.Cookie{
			Name:"baggage",
			Value: base64.StdEncoding.EncodeToString(cypherBytes),
			Domain: r.Host,
			Expires: expire,
		}

		http.SetCookie(w, &cookie)
		http.Redirect(w,r, loginUrl,http.StatusTemporaryRedirect)
	})


	http.HandleFunc(*callbackPath, func(w http.ResponseWriter, r *http.Request) {
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

		oauthStateBytes, err := decrypt(key,decodedValue )
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
		token, err := config.Exchange(ctx, code)
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

	})




	server := http.Server{
		Addr: fmt.Sprintf("0.0.0.0:%d", *port),
		ErrorLog: defaultLog.New(serverJsonWriter{}, "", 0),
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	}
}


func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}



func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{
		FieldMap: log.FieldMap{
			log.FieldKeyTime:  "timestamp",
		},
	})

	log.SetLevel(log.InfoLevel)
	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

}

func writeHtmlErrorResponse(w http.ResponseWriter, e error ){
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(e.Error()))
	return
}
