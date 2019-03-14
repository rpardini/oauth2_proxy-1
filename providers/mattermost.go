package providers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/api"
)

// MattermostProvider represents a Mattermost based Identity Provider
type MattermostProvider struct {
	*ProviderData
	Host string
}

// NewMattermostProvider initiates a new MattermostProvider
func NewMattermostProvider(p *ProviderData) *MattermostProvider {
	p.ProviderName = "Mattermost"
	if p.Scope == "" {
		p.Scope = "public_profile email"
	}
	return &MattermostProvider{ProviderData: p}
}

// Configure defaults the MattermostProvider configuration options
func (p *MattermostProvider) Configure(host string) {
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
	log.Printf("Mattermost LoginURL: %s", p.LoginURL.String())
	log.Printf("Mattermost RedeemURL: %s", p.RedeemURL.String())
	log.Printf("Mattermost ProfileURL: %s", p.ProfileURL.String())
	log.Printf("Mattermost ValidateURL: %s", p.ValidateURL.String())

}

func getMattermostHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	//header.Set("x-li-format", "json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *MattermostProvider) GetEmailAddress(s *SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String()+"", nil)
	if err != nil {
		return "", err
	}
	req.Header = getMattermostHeader(s.AccessToken)

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
func (p *MattermostProvider) GetUserName(s *SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String()+"", nil)
	if err != nil {
		return "", err
	}
	req.Header = getMattermostHeader(s.AccessToken)

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
func (p *MattermostProvider) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, getMattermostHeader(s.AccessToken))
}
