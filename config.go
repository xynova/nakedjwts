package main

import (
	"crypto"
	"flag"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/url"
	"time"
)

type serviceConfig struct {
	oauth2         *oauth2.Config
	stateEncKey    []byte
	maxLoginWindow time.Duration
	sericePort     int
	redirectUrl    url.URL
	privKey crypto.PrivateKey
	pubKey crypto.PublicKey
}



//type Scopes []string
//
//func (s *Scopes) String() string {
//	return fmt.Sprintf("%s", *s)
//}
//
//func (s *Scopes) Set(value string) error {
//	*s = append(*s, value)
//	return nil
//}


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
		//scopesFlag       Scopes
	)


	//flag.Var(&scopesFlag, "scope", "oAuth scopesFlag to authorize (can be specified multiple times")
	flag.Parse()


	// Set log level
	if *debugFlag {
		log.SetLevel(log.DebugLevel)
	}

	redirectUrl,err := url.Parse(*redirectUrlFlag)
	if err != nil{
		log.Fatalf("Cannot parse url %s", *redirectUrl)
		return nil, err
	}


	privKey , err :=  getPrivateKey("./ignore.key.priv")
	if err != nil{
		log.Fatalf("Cannot parse private key: %s", err)
		return nil, err
	}

	pubKey , err :=  getPublicKey("./ignore.key.pub")
	if err != nil{
		log.Fatalf("Cannot public key %s", err)
		return nil, err
	}



	rt := &serviceConfig{

		oauth2: &oauth2.Config{
			ClientID:     *clientIdFlag,
			ClientSecret: *clientSecretFlag,
			//Scopes:       scopesFlag,
			RedirectURL:  redirectUrl.String(),
			Endpoint: oauth2.Endpoint{
				AuthURL:  *authorizeUrlFlag,
				TokenURL: *tokenUrlFlag,
			},
		},
		stateEncKey:    []byte("a very very very very secret key"), // 32 bytes
		sericePort:     *portFlag,
		maxLoginWindow: *loginWindowFlag,
		redirectUrl:    *redirectUrl,
		pubKey: pubKey,
		privKey: privKey,
	}


	return rt, nil
}

