package social

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type SocialLark struct {
	*SocialBase
	hostedDomain      string
	apiUrl            string
	appAccessTokenUrl string
}

type UserInfoContextKey struct{}

func (s *SocialLark) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	response, err := s.httpGet(client, s.apiUrl)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}
	var res AccessTokenAndUserInfo
	err = json.Unmarshal(response.Body, &res)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %s", err)
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("get user info response code is :%d, msg:%s", res.Code, res.Msg)
	}
	data := res.Data
	return &BasicUserInfo{
		Id:    data.UserID,
		Name:  data.Name,
		Email: data.Email,
		Login: data.Email,
	}, nil
}

func (s *SocialLark) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	var buf bytes.Buffer
	c := s.SocialBase.Config
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"},
		"app_id":        {c.ClientID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

func (m *SocialLark) Exchange(ctx context.Context, code string, authOptions ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	c := m.Config
	v := map[string]string{
		"app_id":     c.ClientID,
		"app_secret": c.ClientSecret,
	}
	httpClient := ContextClient(ctx)
	marshal, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", m.appAccessTokenUrl, strings.NewReader(string(marshal)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	r, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch app_access_token: %v", err)
	}
	if statusCode := r.StatusCode; statusCode < 200 || statusCode > 299 {
		return nil, fmt.Errorf("fetch app_access_token err, status code:%d", r.StatusCode)
	}
	var res AppAccessToken
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("app_access_token response code is :%d, msg:%s", res.Code, res.Msg)
	}
	return getAccessTokenByCode(ctx, httpClient, code, c.Endpoint.TokenURL, res.AppAccessToken)
}

func getAccessTokenByCode(ctx context.Context, httpClient *http.Client, code, tokenUrl, appAccessToken string) (*oauth2.Token, error) {
	v := map[string]string{
		"grant_type": "authorization_code",
		"code":       code,
	}
	marshal, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", tokenUrl, strings.NewReader(string(marshal)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", appAccessToken))
	r, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch access_token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("fetch access_token err, status code:%d", r.StatusCode)
	}
	var res AccessTokenAndUserInfo
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("access token response code is :%d, msg:%s", res.Code, res.Msg)
	}
	data := res.Data
	token := &oauth2.Token{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		TokenType:    data.TokenType,
		Expiry:       time.Now().Add(time.Duration(data.ExpiresIn) * time.Second),
	}
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	return token, nil
}

func ContextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	return http.DefaultClient
}

type AppAccessToken struct {
	Code           int32  `json:"code"`
	Msg            string `json:"msg"`
	AppAccessToken string `json:"app_access_token"`
	Expire         int32  `json:"expire"`
}

type AccessTokenAndUserInfo struct {
	Msg  string `json:"msg"`
	Code int64  `json:"code"`
	Data Data   `json:"data"`
}

type Data struct {
	TenantKey        string `json:"tenant_key"`
	OpenID           string `json:"open_id"`
	AvatarBig        string `json:"avatar_big"`
	AvatarThumb      string `json:"avatar_thumb"`
	Mobile           string `json:"mobile"`
	AvatarMiddle     string `json:"avatar_middle"`
	TokenType        string `json:"token_type"`
	EnterpriseEmail  string `json:"enterprise_email"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	AvatarURL        string `json:"avatar_url"`
	UserID           string `json:"user_id"`
	RefreshExpiresIn int32  `json:"refresh_expires_in"`
	Name             string `json:"name"`
	UnionID          string `json:"union_id"`
	EnName           string `json:"en_name"`
	ExpiresIn        int32  `json:"expires_in"`
	Email            string `json:"email"`
}
