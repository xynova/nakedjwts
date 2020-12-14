package main

import (
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/xynova/nakedjwts/pkg/cookies"
	"github.com/xynova/nakedjwts/pkg/localization"
	"github.com/xynova/nakedjwts/pkg/web"
	"golang.org/x/oauth2"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"os"
	"path"
	"time"
)


var(
	app = kingpin.New("nakedjwts", "Serve bare oauth tokens directly to users.")
	doDebug = app.Flag("debug", "Enable debug logs").Default("false").Bool()
	configDir = app.Flag("config-dir","Configuration directory").Default(".").ExistingDir()
	timezone = app.Flag( "timezone", "Timezone").Default("Australia/Sydney").String()
)

func main() {


	configureGlobalFlags(app)
	configureServeCommand(app)
	configureIssueCommand(app)
	kingpin.MustParse(app.Parse(os.Args[1:]))
}

func configureIssueCommand(app *kingpin.Application) {
	// Serve command
	issueCmd := app.Command("issue", "Issue a detached token.")

	surrogateKeyPath := issueCmd.Flag("surrogate-rsa","RSA key to sign the surrogate token").Default("ignore.private.pem").ExistingFile()
	surrogateAudiences := issueCmd.Flag("surrogate-audience","Audiences stamped onto  the surrogate token").Required().Strings()
	surrogateIssuerUrl :=issueCmd.Flag("surrogate-issuer","Issuer stamped onto the surrogate token").Required().URL()

	nameClaim := issueCmd.Flag("name-claim","Name claim issued on surrogate token").Required().String()
	emailClaim := issueCmd.Flag("email-claim","Email claim issued on surrogate token").Required().String()


	issueCmd.Action(func (c *kingpin.ParseContext) error{

		var (
			err   error
		)


		privateKey, err := web.ReadRsaPrivateKey(*surrogateKeyPath)
		if err != nil {
			return err
		}

		// Configure surrogate token funcs
		signingFlow := &web.SigningFlowConfig{
			SigningAlgorithm: jose.RS256,
			PrivateKey:       privateKey,
			KeyId:            "local-default",
			Audiences:        *surrogateAudiences,
			Issuer:           *surrogateIssuerUrl,
			ConfigDir:        *configDir,
		}


		// Get expiry
		today, err := localization.NewLocalTime(*timezone, true)
		if err != nil {
			return err
		}
		// add 7 days
		expires := today.Add(time.Hour * 168)


		// create token
		token, err := signingFlow.IssueSurrogateToken(expires,*nameClaim, *emailClaim, *emailClaim)
		if err != nil {
			return err
		}

		os.Stdout.WriteString(token)

		return nil
	})

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

	surrogateKeyPath := serveCmd.Flag("surrogate-rsa","RSA key to sign the surrogate token").Default("ignore.private.pem").ExistingFile()
	surrogateAudiences := serveCmd.Flag("surrogate-audience","Audiences stamped onto  the surrogate token").Required().Strings()
	surrogateIssuerUrl :=serveCmd.Flag("surrogate-issuer","Issuer stamped onto the surrogate token").Required().URL()


	serveCmd.Action(func (c *kingpin.ParseContext) error{

		var (
			hFunc http.HandlerFunc
			err   error
		)



		privateKey, err := web.ReadRsaPrivateKey(*surrogateKeyPath)
		if err != nil {
			return err
		}

		cookieSetter := &cookies.Encrypted{
			Name: "baggage",
			Key: privateKey,
			Path: path.Join("/",*httpBasePath),
		}

		// Configure oauth login handling funcs
		oauthFlow := &web.OauthFlowConfig{
			StateCookie:       cookieSetter,
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

		signingFlow := &web.SigningFlowConfig{
			StateCookie:      cookieSetter,
			SigningAlgorithm: jose.RS256,
			PrivateKey:       privateKey,
			KeyId:            "local-default",
			Audiences:        *surrogateAudiences,
			Issuer:           *surrogateIssuerUrl,
			ConfigDir:        *configDir,
		}



		router := mux.NewRouter()
		displayTokenPath := path.Join(cookieSetter.Path,"display-token")

		// Starts teh oauth login flow
		hFunc = oauthFlow.LoginInitHandle()
		router.HandleFunc(cookieSetter.Path, hFunc).Methods("GET")
		router.HandleFunc(cookieSetter.Path + "/", hFunc).Methods("GET")

		// Handles the oauth id provider callback code
		displayTokenRedirect := func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, displayTokenPath,http.StatusTemporaryRedirect)
		}
		hFunc = oauthFlow.LoginCallbackHandle(displayTokenRedirect)
		router.HandleFunc(oauthFlow.ClientCallbackUrl.Path, hFunc).Methods("GET")

		// Generates surrogate token
		expiryCalcFunc := func() (time.Time, error) {
			today, err := localization.NewLocalTime(*timezone, true)
			if err != nil {
				return time.Now(),err
			}
			return today.BeginningOfNextMonth(), nil
		}
		hFunc =  signingFlow.RenderSurrogateJwtHandle(expiryCalcFunc)
		router.HandleFunc(displayTokenPath, hFunc).Methods("GET")

		// Displays the jwks public key for the surrogate token validation
		hFunc = signingFlow.RenderJwksHandle()
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

		log.Infof("Timezone: %s",*timezone)
		log.Infof("ConfigDir: %s",*configDir)
		log.Infof("Debug: %t",*doDebug)
		return nil
	})
}
