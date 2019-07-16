package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xynova/nakedjwts/pkg/web"
	"golang.org/x/oauth2"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"os"
)

func main() {

	app := kingpin.New("nakedjwts", "Serve bare oauth tokens directly to users.")
	configureGlobalFlags(app)
	configureServeCommand(app)
	kingpin.MustParse(app.Parse(os.Args[1:]))
}


func configureServeCommand(app *kingpin.Application) {

	// Serve command
	serveCmd := app.Command("serve", "Start the http service.")
	port := serveCmd.Flag("port", "Port to start the service under").Default("8080").Int()
	clientCallbackUrl := serveCmd.Flag("client-callback-url", "Token callback url").Default("http://localhost:8080/oauth2/callback").URL()
	clientId := serveCmd.Flag("client-id", "oauth app clientId").Required().String()
	clientSecret := serveCmd.Flag("client-secret", "oauth app clientSecret").Required().String()
	authorizeUrl := serveCmd.Flag("authorize-url","Idp oauth authorization endpoint").Default("http://localhost/oauth2/authorize").URL()
	tokenUrl := serveCmd.Flag("token-url","Idp oauth token endpoint").Default("http://localhost/oauth2/token").URL()
	maxLoginWindow := serveCmd.Flag("max-login-window", "Max time allowed for login to happen.").Default("30s").Duration()
	privateKeyPath := serveCmd.Flag("private-key-file","RSA key to sign the custom tokens").Default("ignore.key.priv").ExistingFile()

	displayTokenPath := "/display-token"
	jwksPath := "/.well-known/jwks.json"

	serveCmd.Action(func (c *kingpin.ParseContext) error{

		// New server
		var err error
		mux := http.NewServeMux()


		stateCookieConfig := &web.StateCookieConfig{
			Name:   "baggage",
			EncKey: []byte("a very very very very secret key"), // 32 bytes
		}

		// Configure oauth login handling
		oauthFlow := &web.OauthFlowConfig{
			MaxLoginWindow:    *maxLoginWindow,
			ClientCallbackUrl: *clientCallbackUrl,
			Oauth2: &oauth2.Config{
				ClientID:     *clientId,
				ClientSecret: *clientSecret,
				//Scopes:       scopesFlag,
				RedirectURL: (*clientCallbackUrl).String(),
				Endpoint: oauth2.Endpoint{
					AuthURL:  (*authorizeUrl).String(),
					TokenURL: (*tokenUrl).String(),
				},
			},
		}
		displayTokenRedirect := func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, displayTokenPath,http.StatusTemporaryRedirect)
		}

		mux.HandleFunc("/", web.OauthLoginInitHandler(oauthFlow, stateCookieConfig))
		mux.HandleFunc(oauthFlow.ClientCallbackUrl.Path, web.OauthLoginCallbackHandler(oauthFlow ,stateCookieConfig, displayTokenRedirect))


		// Configure jwks keys for local token validation
		privateKey, err := web.ReadRsaPrivateKey(*privateKeyPath)
		if err != nil {
			return err
		}
		signingFlow := &web.SigningFlowConfig{
			SigningAlgorithm: jose.RS256,
			PrivateKey: privateKey,
			KeyId: "local-default",
			Audience: "some-audience",
			Issuer: "issuer-url",
		}
		mux.HandleFunc(jwksPath, web.RenderJwksHandler(signingFlow) )
		mux.HandleFunc(displayTokenPath, web.RenderSurrogateJwtHandler(signingFlow, stateCookieConfig))

		// Start server
		addr := fmt.Sprintf("0.0.0.0:%d", *port)
		if err = http.ListenAndServe(addr, mux); err != http.ErrServerClosed {
			log.Fatalln(err)
		}

		return nil
	})

	//
	//c := &LsCommand{}
	//ls := app.Command("ls", "List files.").Action(c.run)
	//ls.Flag("all", "List all files.").Short('a').BoolVar(&c.All)
}

func configureGlobalFlags(app *kingpin.Application){
	doDebug := app.Flag("debug", "Enable debug logs").Default("false").Bool()

	// Log as JSON instead of the default ASCII formatter.
	//log.SetFormatter(&log.JSONFormatter{
	//	FieldMap: log.FieldMap{
	//		log.FieldKeyTime:  "timestamp",
	//	},
	//})

	log.SetLevel(log.InfoLevel)
	log.SetOutput(os.Stdout)


	app.Action(func (c *kingpin.ParseContext) error{
		// Set log level
		if *doDebug {
			log.SetLevel(log.DebugLevel)
		}
		return nil
	})
}
