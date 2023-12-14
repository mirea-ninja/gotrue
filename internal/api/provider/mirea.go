package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultMireaAPIBase = "login.mirea.ru"
	mireaEmployeeEmail  = "@mirea.ru"
)

type mireaProvider struct {
	*oauth2.Config
	APIPath string
}

type mireaStudent struct {
	GroupName string `json:"group_name"`
}

type mireaEmployee struct {
	Title     string `json:"title"`      // Должность
	GroupName string `json:"group_name"` // Подразделение
	IpPhone   string `json:"ip_phone"`
}

type mireaUser struct {
	Name       string `json:"name"`
	LastName   string `json:"lastname"`
	MiddleName string `json:"middlename"`
	UserID     string `json:"uid"`
	UserName   string `json:"username"`
	Email      string `json:"email"`
}

// NewMireaProvider creates a RTU MIREA oauth provider.
func NewMireaProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultMireaAPIBase)

	oauthScopes := []string{
		"basic", "student", "employee",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &mireaProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth2/v1/authorize/",
				TokenURL: authHost + "/oauth2/v1/token/",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIPath: authHost,
	}, nil
}

func (p mireaProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p mireaProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u mireaUser
	if err := makeRequest(ctx, tok, p.Config, p.APIPath+"/resources/v1/userinfo", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("unable to find email with Mirea provider")
	}

	var s mireaStudent
	var e mireaEmployee
	if strings.Contains(u.Email, mireaEmployeeEmail) {
		if err := makeRequest(ctx, tok, p.Config, p.APIPath+"/resources/v1/employee", &e); err != nil {
			return nil, err
		}
	} else {
		if err := makeRequest(ctx, tok, p.Config, p.APIPath+"/resources/v1/student", &s); err != nil {
			return nil, err
		}
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        p.APIPath,
			Subject:       u.UserID,
			Name:          u.Name,
			FamilyName:    u.LastName,
			MiddleName:    u.MiddleName,
			Email:         u.Email,
			EmailVerified: true,
			ProviderId:    u.UserID,
			CustomClaims: map[string]interface{}{
				"student":  s,
				"employee": e,
			},
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}},
	}, nil
}
