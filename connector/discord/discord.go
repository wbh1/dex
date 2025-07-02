package discord

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/dexidp/dex/connector"
	"golang.org/x/oauth2"
	"log/slog"
)

type discordConnector struct {
	clientID                string
	clientSecret            string
	redirectURI             string
	guildID                 string
	disableCheckGuildMember bool
	logger                  *slog.Logger
}

type Config struct {
	ClientID                string `json:"clientID"`
	ClientSecret            string `json:"clientSecret"`
	RedirectURI             string `json:"redirectURI"`
	GuildID                 string `json:"guildID"`
	DisableCheckGuildMember bool   `json:"disableCheckGuildMember"`
}

func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	return &discordConnector{
		clientID:                c.ClientID,
		clientSecret:            c.ClientSecret,
		redirectURI:             c.RedirectURI,
		guildID:                 c.GuildID,
		disableCheckGuildMember: c.DisableCheckGuildMember,
		logger:                  logger.With(slog.Group("connector", "type", "discord", "id", id)),
	}, nil
}

func (c *discordConnector) newOAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://discord.com/api/oauth2/authorize",
			TokenURL:  "https://discord.com/api/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: c.redirectURI,
		Scopes:      []string{"identify", "email", "guilds.members.read"},
	}
}

func (c *discordConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	return c.newOAuth2Config().AuthCodeURL(state), nil
}

func (c *discordConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, errors.New(q.Get("error_description"))
	}

	ctx := r.Context()
	token, err := c.newOAuth2Config().Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("discord connector: failed to get token: %v", err)
	}

	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	if !c.disableCheckGuildMember {
		identity.PreferredUsername, err = getGuildMember(client, c.guildID)
		if err != nil {
			return identity, fmt.Errorf("discord connector: failed to get guild member: %v", err)
		}
	}

	userInfoResp, err := client.Get("https://discord.com/api/v10/users/@me")
	if err != nil {
		return identity, fmt.Errorf("discord connector: failed to execute request to userinfo: %v", err)
	}
	defer userInfoResp.Body.Close()

	if userInfoResp.StatusCode != http.StatusOK {
		return identity, fmt.Errorf("discord connector: failed to execute request to userinfo: status %d", userInfoResp.StatusCode)
	}

	var userInfoResult map[string]interface{}
	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfoResult); err != nil {
		return identity, fmt.Errorf("discord connector: failed to parse userinfo: %v", err)
	}

	userID, found := userInfoResult["id"]
	if !found {
		return identity, errors.New("discord connector: not found id claim")
	}

	switch userID.(type) {
	case float64, int64, string:
		identity.UserID = fmt.Sprintf("%v", userID)
	default:
		return identity, fmt.Errorf("discord connector: id claim should be string or number, got %T", userID)
	}

	identity.Username, _ = userInfoResult["username"].(string)
	identity.Email, _ = userInfoResult["email"].(string)
	identity.EmailVerified, _ = userInfoResult["verified"].(bool)

	if identity.PreferredUsername == "" {
		identity.PreferredUsername = identity.Username
	}
	return identity, nil
}

func getGuildMember(client *http.Client, guildID string) (nick string, err error) {
	url := fmt.Sprintf("https://discord.com/api/users/@me/guilds/%s/member", guildID)
	res, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusNotFound {
			return "", fmt.Errorf("not guild member")
		}

		resBody, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("failed to request guilds member: status %d, body %s", res.StatusCode, string(resBody))
	}

	var result map[string]any
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return "", err
	}

	nick, _ = result["nick"].(string)
	return nick, nil
}
