package main

import (
	"flag"
	"golang.org/x/oauth2"
	"net/url"
	"time"
	log "github.com/sirupsen/logrus"
)

type serviceConfig struct {
	oauth2 *oauth2.Config
	stateKey []byte
	loginWindow time.Duration
	servePort int
	redirectUrl url.URL
}



func getConfig() ( *serviceConfig, error){
	var (
		portFlag         = flag.Int("port", 8080, "Server port")
		redirectUrlFlag  = flag.String("redirect-url", "http://localhost:8080/oauth2/callback", "Token callback url")
		clientIdFlag     = flag.String("client-id", "", "Client ID")
		clientSecretFlag = flag.String("client-secret", "", "Client secret")
		authorizeUrlFlag = flag.String("authorize-url", "https://localhost/oauth2/authorize", "Authorization URL")
		tokenUrlFlag     = flag.String("token-url", "https://localhost/oauth2/token", "Token URL")
		loginWindowFlag  = flag.Duration("login-window", 30 * time.Second, "Max time allowed for login to happen. eg: 30s")
		debugFlag        = flag.Bool("debug", false, "Turn verbose logs on")
		scopesFlag       Scopes
	)


	flag.Var(&scopesFlag, "scope", "oAuth scopesFlag to authorize (can be specified multiple times")
	flag.Parse()


	// Set log level
	if *debugFlag {
		log.SetLevel(log.DebugLevel)
	}

	redirectUrl,err := url.Parse(*redirectUrlFlag)
	if err != nil{
		log.Fatalf("Cannot parse url %s", *redirectUrl)
	}

	rt := &serviceConfig{

		oauth2: &oauth2.Config{
			ClientID:     *clientIdFlag,
			ClientSecret: *clientSecretFlag,
			Scopes:       scopesFlag,
			RedirectURL:  redirectUrl.String(),
			Endpoint: oauth2.Endpoint{
				AuthURL:  *authorizeUrlFlag,
				TokenURL: *tokenUrlFlag,
			},
		},
		stateKey: []byte("a very very very very secret key"), // 32 bytes
		servePort: *portFlag,
		loginWindow: *loginWindowFlag,
		redirectUrl: *redirectUrl,
	}


	return rt, nil
}
