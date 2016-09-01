package cattleya

import (
    "github.com/garyburd/go-oauth/oauth"
)

const (
	refreshTokenURL  = "https://api.twitter.com/oauth/request_token"
	authorizationURL = "https://api.twitter.com/oauth/authenticate"
	accessTokenURL   = "https://api.twitter.com/oauth/access_token"
	accountURL       = "https://api.twitter.com/1.1/account/verify_credentials.json"
)

type Twitter struct {
    TwitterKey    string
    TwitterSecret string
}

//  func NewTwitter(key string, secret string) *Twitter {
//      return &Twitter{
//          twitterKey: key,
//          twitterSecret: secret
//      }
//  }

func (t Twitter) NewOauthClient() *oauth.Client {
	oc := &oauth.Client{
		TemporaryCredentialRequestURI: refreshTokenURL,
		ResourceOwnerAuthorizationURI: authorizationURL,
		TokenRequestURI:               accessTokenURL,
		Credentials: oauth.Credentials{
			Token:  t.TwitterKey,
			Secret: t.TwitterSecret,
		},
	}

	return oc
}

