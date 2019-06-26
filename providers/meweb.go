package providers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/api"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
)

// MewebProvider represents a Meweb based Identity Provider
type MewebProvider struct {
	*ProviderData
	Host string
}

// NewMewebProvider initiates a new MewebProvider
func NewMewebProvider(p *ProviderData) *MewebProvider {
	p.ProviderName = "Meweb"
	if p.Scope == "" {
		p.Scope = "user.basic"
	}
	return &MewebProvider{ProviderData: p}
}

// Configure defaults the MewebProvider configuration options
func (p *MewebProvider) Configure(host string) {
	p.Host = host
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: p.Host,
			Path: "/oauth/authorize",
			// ?granted_scopes=true
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: p.Host,
			Path: "/oauth/access_token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: p.Host,
			Path: "/api/v4/users/me",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	log.Printf("Meweb LoginURL: %s", p.LoginURL.String())
	log.Printf("Meweb RedeemURL: %s", p.RedeemURL.String())
	log.Printf("Meweb ProfileURL: %s", p.ProfileURL.String())
	log.Printf("Meweb ValidateURL: %s", p.ValidateURL.String())

}

func getMewebHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	//header.Set("x-li-format", "json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *MewebProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String()+"", nil)
	if err != nil {
		return "", err
	}
	req.Header = getMewebHeader(s.AccessToken)

	type result struct {
		Email string
	}
	var r result
	err = api.RequestJSON(req, &r)
	if err != nil {
		return "", err
	}
	if r.Email == "" {
		return "", errors.New("no email")
	}
	return r.Email, nil
}

// GetUserName returns the Account username address
func (p *MewebProvider) GetUserName(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String()+"", nil)
	if err != nil {
		return "", err
	}
	req.Header = getMewebHeader(s.AccessToken)

	type result struct {
		Username string
	}
	var r result
	err = api.RequestJSON(req, &r)
	if err != nil {
		return "", err
	}
	if r.Username == "" {
		return "", errors.New("no username")
	}
	return r.Username, nil
}

// ValidateSessionState validates the AccessToken
func (p *MewebProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getMewebHeader(s.AccessToken))
}
