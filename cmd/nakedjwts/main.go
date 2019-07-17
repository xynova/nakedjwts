package main

import (
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xynova/nakedjwts/pkg/web"
	"golang.org/x/oauth2"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"os"
	"path"
)


var(
	configDirFlagName = "config-dir"
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
	httpBasePath := serveCmd.Flag("http-base", "Modify ").Default("/").String()
	httpPort := serveCmd.Flag("http-port", "Port to start the service under").Default("8080").Int()
	clientCallbackUrl := serveCmd.Flag("client-callback-url", "Token callback url").Default("http://localhost:8080/oauth2/callback").URL()
	clientId := serveCmd.Flag("client-id", "oauth app clientId").Required().String()
	clientSecret := serveCmd.Flag("client-secret", "oauth app clientSecret").Required().String()
	idAuthorizeUrl := serveCmd.Flag("id-authorize-url","Idp oauth authorization endpoint").Default("http://localhost/oauth2/authorize").URL()
	idTokenUrl := serveCmd.Flag("id-token-url","Idp oauth token endpoint").Default("http://localhost/oauth2/token").URL()
	idLoginWindow := serveCmd.Flag("id-login-window", "Max time allowed for login to happen.").Default("30s").Duration()

	surrogateKeyPath := serveCmd.Flag("surrogate-rsa","RSA key to sign the surrogate token").Default("ignore.key.priv").ExistingFile()
	surrogateAudiences := serveCmd.Flag("surrogate-audience","Audiences stamped onto  the surrogate token").Required().Strings()
	surrogateIssuerUrl :=serveCmd.Flag("surrogate-issuer","Issuer stamped onto the surrogate token").Required().URL()

	configDir := app.GetFlag(configDirFlagName).Default(".").ExistingDir()


	serveCmd.Action(func (c *kingpin.ParseContext) error{

		var (
			hFunc http.HandlerFunc
			err   error
		)

		// Configure oauth login handling funcs
		oauthFlow := &web.OauthFlowConfig{
			MaxLoginWindow:    *idLoginWindow,
			ClientCallbackUrl: *clientCallbackUrl,
			Oauth2: &oauth2.Config{
				ClientID:     *clientId,
				ClientSecret: *clientSecret,
				//Scopes:       scopesFlag,
				RedirectURL: (*clientCallbackUrl).String(),
				Endpoint: oauth2.Endpoint{
					AuthURL:  (*idAuthorizeUrl).String(),
					TokenURL: (*idTokenUrl).String(),
				},
			},
		}


		// Configure surrogate token funcs
		privateKey, err := web.ReadRsaPrivateKey(*surrogateKeyPath)
		if err != nil {
			return err
		}
		signingFlow := &web.SigningFlowConfig{
			SigningAlgorithm: jose.RS256,
			PrivateKey: privateKey,
			KeyId: "local-default",
			Audiences: *surrogateAudiences,
			Issuer: *surrogateIssuerUrl,
			ConfigDir: *configDir,
		}


		stateCookieConfig := &web.StateCookieConfig{
			Name:   "baggage",
			EncKey: []byte("a very very very very secret key"), // 32 bytes
			Path: path.Join("/",*httpBasePath),
		}



		router := mux.NewRouter()
		displayTokenPath := path.Join(stateCookieConfig.Path,"display-token")

		// Starts teh oauth login flow
		hFunc = web.OauthLoginInitHandler(oauthFlow, stateCookieConfig)
		router.HandleFunc(stateCookieConfig.Path, hFunc).Methods("GET")
		router.HandleFunc(stateCookieConfig.Path + "/", hFunc).Methods("GET")

		// Handles the oauth id provider callback code
		displayTokenRedirect := func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, displayTokenPath,http.StatusTemporaryRedirect)
		}
		hFunc = web.OauthLoginCallbackHandler(oauthFlow ,stateCookieConfig, displayTokenRedirect)
		router.HandleFunc(oauthFlow.ClientCallbackUrl.Path, hFunc).Methods("GET")

		// Generates surrogate token
		hFunc =  web.RenderSurrogateJwtHandler(signingFlow, stateCookieConfig)
		router.HandleFunc(displayTokenPath, hFunc).Methods("GET")

		// Displays the jwks public key for the surrogate token validation
		hFunc = web.RenderJwksHandler(signingFlow)
		router.HandleFunc("/{base:.*}.well-known/jwks.json", hFunc).Methods("GET")


		// Start server
		addr := fmt.Sprintf("0.0.0.0:%d", *httpPort)
		log.Infof("Listening on: %s", addr)
		if err = http.ListenAndServe(addr, router); err != http.ErrServerClosed {
			log.Fatalln(err)
		}

		return nil
	})

}

func configureGlobalFlags(app *kingpin.Application){
	doDebug := app.Flag("debug", "Enable debug logs").Default("false").Bool()
	app.Flag(configDirFlagName,"Configuration directory").Default(".").ExistingDir()


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
