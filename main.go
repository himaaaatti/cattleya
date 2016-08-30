package main

import (
    "github.com/garyburd/go-oauth/oauth"
    "github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"

	"github.com/pkg/errors"

	"os"
	"net/http"
    "encoding/json"
    "fmt"
)

const (
	refreshTokenURL  = "https://api.twitter.com/oauth/request_token"
	authorizationURL = "https://api.twitter.com/oauth/authenticate"
	accessTokenURL   = "https://api.twitter.com/oauth/access_token"
	accountURL       = "https://api.twitter.com/1.1/account/verify_credentials.json"
)

var (
	twitterKey    string
	twitterSecret string
    domain int
    callbackURL string
)

func NewTWClient() *oauth.Client {
	oc := &oauth.Client{
		TemporaryCredentialRequestURI: refreshTokenURL,
		ResourceOwnerAuthorizationURI: authorizationURL,
		TokenRequestURI:               accessTokenURL,
		Credentials: oauth.Credentials{
			Token:  twitterKey,
			Secret: twitterSecret,
		},
	}

	return oc
}

func LoginByTwitter(c *gin.Context) {
    oc := NewTWClient()

    rt, err := oc.RequestTemporaryCredentials(nil, callbackURL, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, nil)
        panic(err)
		return
	}

    session := sessions.Default(c)
    session.Set("request_token", rt.Token)
    session.Set("request_token_secret", rt.Secret)
    session.Save()

    url := oc.AuthorizationURL(rt, nil)

	c.Redirect(http.StatusMovedPermanently, url)
	return
}

func TwitterCallback(c *gin.Context) {
    tok := c.DefaultQuery("oauth_token", "")
    if tok == "" {
        c.JSON(http.StatusBadRequest, nil)
        return
    }

    ov := c.DefaultQuery("oauth_verifier", "")
    if ov == "" {
        c.JSON(http.StatusBadRequest, nil)
        return
    }

    session := sessions.Default(c)
    v := session.Get("request_token")
    if v == nil {
        c.JSON(http.StatusBadRequest, nil)
        return
    }
    rt := v.(string)
    if tok != rt {
        c.JSON(http.StatusBadRequest, nil)
        return
    }

    v = session.Get("request_token_secret")
    if v == nil {
        c.JSON(http.StatusBadRequest, nil)
        return
    }
    rts := v.(string)
    if rts == "" {
        c.JSON(http.StatusBadRequest, nil)
        return
    }

    code, at, err := GetAccessToken(&oauth.Credentials{Token: rt, Secret: rts}, ov)
    if err != nil {
        c.JSON(code, nil)
        return
    }

    account := struct {
        ID         string `json:"id_str"`
        ScreenName string `json:"screen_name"`
    }{}
    code, err = GetMe(at, &account)
    if err != nil {
        c.JSON(code, nil)
        return
    }
    session.Set("user_id", account.ID)
    session.Save()

    fmt.Println(account)
    fmt.Println(at)

    c.Redirect(http.StatusMovedPermanently, "/")

    return
}

func GetAccessToken(rt *oauth.Credentials, oauthVerifier string) (int, *oauth.Credentials, error) {
	oc := NewTWClient()
	at, _, err := oc.RequestToken(nil, rt, oauthVerifier)
	if err != nil {
		err := errors.Wrap(err, "Failed to get access token.")
		return http.StatusBadRequest, nil, err
	}

	return http.StatusOK, at, nil
}

func GetMe(at *oauth.Credentials, user interface{}) (int, error) {
	oc := NewTWClient()
	resp, err := oc.Get(nil, at, accountURL, nil)
	if err != nil {
		err = errors.Wrap(err, "Failed to send twitter request.")
		return http.StatusInternalServerError, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		err = errors.New("Twitter is unavailable")
		return http.StatusInternalServerError, err
	}

	if resp.StatusCode >= 400 {
		err = errors.New("Twitter request is invalid")
		return http.StatusBadRequest, err
	}

	err = json.NewDecoder(resp.Body).Decode(user)
	if err != nil {
		err = errors.Wrap(err, "Failed to decode user account response.")
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func main() {

    twitterKey = os.Getenv("TEST_KEY")
    twitterSecret = os.Getenv("TEST_SECRET")

    if (twitterKey == "")  || (twitterSecret == "") {
        panic("you should set TEST_KEY and TEST_SECRET")
    }

    domain := os.Getenv("DOMAIN")
    if domain == "" {
        panic("you should set DOMAIN env varibale")
    }

    port := os.Getenv("PORT")
    if port == "" {
        panic("you should set PORT env variable")
    }

    url := "http://" + domain + ":" + port + "/"
    callbackURL = url + "login/callback"

    router := gin.New()
    //      router := gin.Default()

    //      router.LoadHTMLTemplates("templates/*")
//      router.LoadHTMLFiles("templates/index_to_login.tmpl")
//      router.LoadHTMLFiles("templates/main.tmpl")
    router.LoadHTMLGlob("templates/*")

    store := sessions.NewCookieStore([]byte("secret"))
    router.Use(sessions.Sessions("mysession", store))

    router.Use(gin.Logger())
    router.Use(gin.Recovery())

    //      router.GET("/", func(c *gin.Context) {
    //          session := sessions.Default(c)

    //          co := session.Get("counter")

    //          var counter int
    //          if co == nil {
    //              counter = 1
    //          }else {
    //              counter = co.(int)
    //          }

    //          uid_t := session.Get("user_id")
    //          var userId string
    //          if uid_t == nil {
    //              userId = "null"
    //          }else {
    //              userId = uid_t.(string)
    //          }

    //          result := struct {
    //              Count int
    //              UserId string
    //          }{Count: counter, UserId: userId}

    //          fmt.Println(counter)
    //          session.Set("counter", counter + 1)
    //          session.Save()
    //          c.JSON(http.StatusOK, result)
    //      })

    router.GET("/login", LoginByTwitter)
    router.GET("/login/callback", TwitterCallback)

    router.GET("/logout", func(c *gin.Context) {
        session := sessions.Default(c)
        session.Clear()
        session.Save()
        c.Redirect(http.StatusMovedPermanently, "/")
    })

    router.GET("/", func(c *gin.Context) {
        session := sessions.Default(c)
        user_id := session.Get("user_id")
        if user_id == nil {
            //TODO show page that have button 
            c.HTML(http.StatusOK, "index_to_login.tmpl", nil)
            return
        }

        // pass authorized
        //TODO
        c.HTML(http.StatusOK, "main.tmpl", nil)
    })

    router.Run()
}

