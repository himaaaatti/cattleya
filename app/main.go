package cattleya

import (
    "github.com/garyburd/go-oauth/oauth"
    "github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"

	"github.com/pkg/errors"

//      _ "github.com/mattn/go-sqlite3"
    _ "github.com/go-sql-driver/mysql"

	"os"
	"net/http"
    "encoding/json"
    "fmt"

    "database/sql"

)

var (
    callbackURL string
    twitterOauth *Twitter
    db *sql.DB
)

// expenses, incomes
type MoneyInfo struct {
    ID int
    Budget int
    Date string
    IsOUTGO bool
}

func LoginByTwitter(c *gin.Context) {
    oc := twitterOauth.NewOauthClient()

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

    row := db.QueryRow(`SELECT count(1) FROM users WHERE id = ?`, account.ID)
    var count int
    err = row.Scan(&count)
    if err != nil {
        panic(err)
    }

    if count == 0 {
        _, err = db.Exec(
            `INSERT INTO users (id , token, secret ,name) VALUES (?, ?, ?, ?)`,
            account.ID, at.Token, at.Secret, account.ScreenName)
        if err != nil {
            panic(err)
        }
    }
    //TODO
//      else {
//          _, err = db.Exec(`SELECT text FROM users WHERE id = ?`, account.ID)
//      }

    session.Set("user_id", account.ID)
    session.Set("name", account.ScreenName)
    session.Save()

    fmt.Println(account)
    fmt.Println(at)

    c.Redirect(http.StatusMovedPermanently, "/")

    return
}

func GetAccessToken(rt *oauth.Credentials, oauthVerifier string) (int, *oauth.Credentials, error) {
	oc := twitterOauth.NewOauthClient()
	at, _, err := oc.RequestToken(nil, rt, oauthVerifier)
	if err != nil {
		err := errors.Wrap(err, "Failed to get access token.")
		return http.StatusBadRequest, nil, err
	}

	return http.StatusOK, at, nil
}

func GetMe(at *oauth.Credentials, user interface{}) (int, error) {
    accountURL  := "https://api.twitter.com/1.1/account/verify_credentials.json"
	oc := twitterOauth.NewOauthClient()
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

//      fmt.Println(resp.Body)
	err = json.NewDecoder(resp.Body).Decode(user)
	if err != nil {
		err = errors.Wrap(err, "Failed to decode user account response.")
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func main() {

    key := os.Getenv("KEY")
    secret := os.Getenv("SECRET")

    if (key == "")  || (secret == "") {
        panic("you should set KEY and SECRET")
    }

    domain := os.Getenv("DOMAIN")
    if domain == "" {
        panic("you should set DOMAIN env variable")
    }

    port := os.Getenv("PORT")
    if port == "" {
        panic("you should set PORT env variable")
    }

    url := "http://" + domain + ":" + port + "/"
    callbackURL = url + "login/callback"

    dbUser := "root"//os.Getenv("MYSQL_USER")
    if dbUser == "" {
        panic("you should set MYSQL_USER env variable")
    }

    dbPass := os.Getenv("MYSQL_PASSWORD")
    if dbPass == "" {
        panic("you should set MYSQL_PASSWORD env variable")
    }

    dbName := os.Getenv("MYSQL_DATABASE")
    if dbName == "" {
        panic("you should set MYSQL_DATABASE env variable")
    }

    dbHost := os.Getenv("MYSQL_HOST")
    if dbHost == "" {
        dbHost = "mysql"
    }

    // for db
    var err error
//      db, err = sql.Open("sqlite3", "sample.db")
    db, err = sql.Open("mysql", dbUser + ":" + dbPass + "@tcp(" + dbHost +":3306)/"+dbName)


    if err != nil {
        panic(err)
    }

    // for twitter oauth
    twitterOauth = &Twitter{key, secret}

//      router := gin.New()
    router := gin.Default()

    router.LoadHTMLGlob("templates/*")

    store := sessions.NewCookieStore([]byte("secret"))
    router.Use(sessions.Sessions("mysession", store))

    router.Use(gin.Logger())
    router.Use(gin.Recovery())

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

        rows, err := db.Query(
            `SELECT id, budget, type, date from journal WHERE user_id = ?`,
            user_id)
        if err != nil {
            panic(err)
        }

//          expenses := make([]MoneyInfo, 0, 10)
        journal := make([]MoneyInfo, 0)
        for rows.Next() {
            ex := MoneyInfo{}
            var btype string
            err = rows.Scan(&ex.ID, &ex.Budget, &btype, &ex.Date)
            if err != nil {
                panic(err)
            }

            ex.IsOUTGO = btype == "OUTGO"

            fmt.Println(ex)
            journal = append(journal , ex)
        }


        // pass authorized
        c.HTML(http.StatusOK,
            "main.tmpl",
            gin.H{"name": session.Get("name"), "journal": journal })
    })

//      router.GET("/input", func(c *gin.Context) {
//          session := sessions.Default(c)
//          user_id := session.Get("user_id")
//          name := session.Get("name")
//          if name == "" {
//              c.Redirect(http.StatusMovedPermanently, "/")
//              return
//          }

//          rows, err := db.Query(
//              `SELECT id, value, date from expenses WHERE user_id = ? LIMIT 10`,
//              user_id)
//          if err != nil {
//              panic(err)
//          }

//          expenses := make([]Expense, 0, 10)
//          for rows.Next() {
//              ex := Expense{}
//              err = rows.Scan(&ex.ID, &ex.Value, &ex.Date)
//              if err != nil {
//                  panic(err)
//              }
//              expenses = append(expenses, ex)
//          }

//          rows.Close()

//          c.HTML(http.StatusOK, "input.tmpl",
//              gin.H{"name": name, "expenses": expenses})
//      })

//      router.POST("/input", func(c *gin.Context) {
//          session := sessions.Default(c)
//          name := session.Get("name")
//          user_id := session.Get("user_id")
//          if name == "" {
//              c.Redirect(http.StatusMovedPermanently, "/")
//              return
//          }

//          value := c.PostForm("value")
        //TODO now 以外
//          _, err := db.Exec(
//              `INSERT INTO expenses (user_id, value, date) VALUES (?, ?, strftime('%s', 'now'))`,
//              user_id, value)

//          if err != nil {
//              panic(err)
//          }

//          c.Redirect(http.StatusMovedPermanently, "/input")
//      })


    json := router.Group("json")
    {
        json.POST("/submit", func(c *gin.Context) {
            session := sessions.Default(c)
            user_id := session.Get("user_id")

            failedResponse := func() {c.JSON(400, gin.H{"status": "failed"})}
            if user_id == nil {
//                  panic(err)
//                  c.JSON(400,
//                      gin.H{ "status": "failed" })
                failedResponse()
                return
            }

            //TODO
            fmt.Println(c.PostForm("date"))

            //data, budget, move
            date := c.PostForm("date")
            budget := c.PostForm("budget")

            btype := c.PostForm("budget_type")

            var query string
            if btype == "outgo" {
                query = `INSERT INTO journal(user_id, budget, type, date) VALUES (?, ?, 'OUTGO', ?)`
            } else if btype == "income" {
                query = `INSERT INTO journal(user_id, budget, type, date) VALUES (?, ?, 'INCOME', ?)`
            } else {
                failedResponse()
                return
            }

            _, err := db.Exec(query, user_id, budget, date)
            if err != nil {
                panic(err)
            }

            c.JSON(http.StatusOK,
                gin.H{ "status": "ok",
                "budget_type": btype,
                "date": date,
                "budget": budget,
                })
        })
    }

    router.Run()
}

