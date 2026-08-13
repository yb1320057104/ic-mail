package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ConfigPath                   string `json:"-"`
	Host                         string `json:"host"`
	Port                         int    `json:"port"`
	DataPath                     string `json:"data_path"`
	APIKey                       string `json:"api_key"`
	PublicBaseURL                string `json:"public_base_url"`
	ICloudDefaultHost            string `json:"icloud_default_host"`
	ICloudClientID               string `json:"icloud_client_id"`
	AppleAccountAPIKey           string `json:"apple_account_api_key"`
	AppleAccountKeepAliveEnabled bool   `json:"apple_account_keep_alive_enabled"`
	AppleAccountKeepAliveMS      int    `json:"apple_account_keep_alive_ms"`
	MailWatcherEnabled           bool   `json:"mail_watcher_enabled"`
	MailWatcherPollMS            int    `json:"mail_watcher_poll_ms"`
	MailWatcherFetchLimit        int    `json:"mail_watcher_fetch_limit"`
	MailWatcherInitialFetchLimit int    `json:"mail_watcher_initial_fetch_limit"`
	MailWatcherLookbackHours     int    `json:"mail_watcher_lookback_hours"`
	MailRetentionDays            int    `json:"mail_retention_days"`
	MailMaxPerMailbox            int    `json:"mail_max_per_mailbox"`
	PublicFastSyncWaitMS         int    `json:"public_fast_sync_wait_ms"`
	PublicSyncMinIntervalMS      int    `json:"public_sync_min_interval_ms"`
	UpdateEnabled                bool   `json:"update_enabled"`
	UpdateRepository             string `json:"update_repository"`
	UpdateManifestURL            string `json:"update_manifest_url"`
	UpdateAssetName              string `json:"update_asset_name"`
	RegistrationEnabled          bool   `json:"registration_enabled"`
	RegistrationInviteCode       string `json:"registration_invite_code"`
	LoginRateLimitPerIP          int    `json:"login_rate_limit_per_ip"`
	LoginRateLimitPerUsername    int    `json:"login_rate_limit_per_username"`
	LoginRateLimitWindowSeconds  int    `json:"login_rate_limit_window_seconds"`
	LoginBackoffMaxSeconds       int    `json:"login_backoff_max_seconds"`
	LoginCaptchaEnabled          bool   `json:"login_captcha_enabled"`
	AutoLoginSecret              string `json:"-"`
	EasyProxiesURL               string `json:"easy_proxies_url"`
	EasyProxiesPassword          string `json:"-"`
	EasyProxiesHost              string `json:"easy_proxies_host"`
}

func LoadConfig(path string) (Config, error) {
	cfg := Config{
		ConfigPath:                   path,
		Host:                         "127.0.0.1",
		Port:                         8787,
		DataPath:                     filepath.Join("data", "state.json"),
		APIKey:                       strings.TrimSpace(os.Getenv("IPM_API_KEY")),
		PublicBaseURL:                strings.TrimRight(strings.TrimSpace(os.Getenv("IPM_PUBLIC_BASE_URL")), "/"),
		ICloudDefaultHost:            "www.icloud.com.cn",
		ICloudClientID:               defaultAppleOAuthClientID,
		AppleAccountAPIKey:           strings.TrimSpace(os.Getenv("IPM_APPLE_ACCOUNT_API_KEY")),
		AppleAccountKeepAliveEnabled: envBool("APPLE_ACCOUNT_KEEP_ALIVE_ENABLED", true),
		AppleAccountKeepAliveMS:      envPositiveInt("APPLE_ACCOUNT_KEEP_ALIVE_MS", 240000),
		MailWatcherEnabled:           envBool("MAIL_WATCHER_ENABLED", true),
		MailWatcherPollMS:            envPositiveInt("MAIL_WATCHER_POLL_MS", 3000),
		MailWatcherFetchLimit:        envPositiveInt("MAIL_WATCHER_FETCH_LIMIT", 8),
		MailWatcherInitialFetchLimit: envPositiveInt("MAIL_WATCHER_INITIAL_FETCH_LIMIT", 20),
		MailWatcherLookbackHours:     envPositiveInt("MAIL_WATCHER_LOOKBACK_HOURS", 24),
		MailRetentionDays:            envPositiveInt("MAIL_RETENTION_DAYS", 60),
		MailMaxPerMailbox:            envPositiveInt("MAIL_MAX_PER_MAILBOX", 200),
		PublicFastSyncWaitMS:         envPositiveInt("PUBLIC_FAST_SYNC_WAIT_MS", 600),
		PublicSyncMinIntervalMS:      envPositiveInt("PUBLIC_SYNC_MIN_INTERVAL_MS", 3000),
		UpdateEnabled:                envBool("IPM_UPDATE_ENABLED", true),
		UpdateRepository:             firstNonEmptyString(strings.TrimSpace(os.Getenv("IPM_UPDATE_REPOSITORY")), "yb1320057104/ic-mail"),
		UpdateManifestURL:            strings.TrimSpace(os.Getenv("IPM_UPDATE_MANIFEST_URL")),
		UpdateAssetName:              strings.TrimSpace(os.Getenv("IPM_UPDATE_ASSET_NAME")),
		RegistrationEnabled:          envBool("IPM_REGISTRATION_ENABLED", false),
		RegistrationInviteCode:       strings.TrimSpace(os.Getenv("IPM_REGISTRATION_INVITE_CODE")),
		LoginRateLimitPerIP:          envPositiveInt("IPM_LOGIN_RATE_LIMIT_PER_IP", 5),
		LoginRateLimitPerUsername:    envPositiveInt("IPM_LOGIN_RATE_LIMIT_PER_USERNAME", 5),
		LoginRateLimitWindowSeconds:  envPositiveInt("IPM_LOGIN_RATE_LIMIT_WINDOW_SECONDS", 600),
		LoginBackoffMaxSeconds:       envPositiveInt("IPM_LOGIN_BACKOFF_MAX_SECONDS", 600),
		LoginCaptchaEnabled:          envBool("IPM_LOGIN_CAPTCHA_ENABLED", true),
		AutoLoginSecret:              strings.TrimSpace(os.Getenv("IPM_AUTO_LOGIN_SECRET")),
		EasyProxiesURL:               firstNonEmptyString(strings.TrimRight(strings.TrimSpace(os.Getenv("IPM_EASY_PROXIES_URL")), "/"), "http://127.0.0.1:9091"),
		EasyProxiesPassword:          strings.TrimSpace(os.Getenv("IPM_EASY_PROXIES_PASSWORD")),
		EasyProxiesHost:              firstNonEmptyString(strings.TrimSpace(os.Getenv("IPM_EASY_PROXIES_HOST")), "127.0.0.1"),
	}
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, err
	}
	var fromFile Config
	if err := json.Unmarshal(data, &fromFile); err != nil {
		return Config{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Config{}, err
	}
	if fromFile.Host != "" {
		cfg.Host = fromFile.Host
	}
	if fromFile.Port != 0 {
		cfg.Port = fromFile.Port
	}
	if fromFile.DataPath != "" {
		cfg.DataPath = fromFile.DataPath
	}
	if strings.TrimSpace(fromFile.APIKey) != "" {
		cfg.APIKey = strings.TrimSpace(fromFile.APIKey)
	}
	if strings.TrimSpace(fromFile.PublicBaseURL) != "" {
		cfg.PublicBaseURL = strings.TrimRight(strings.TrimSpace(fromFile.PublicBaseURL), "/")
	}
	if strings.TrimSpace(fromFile.ICloudDefaultHost) != "" {
		cfg.ICloudDefaultHost = strings.TrimSpace(fromFile.ICloudDefaultHost)
	}
	if strings.TrimSpace(fromFile.ICloudClientID) != "" {
		cfg.ICloudClientID = strings.TrimSpace(fromFile.ICloudClientID)
	}
	if strings.TrimSpace(fromFile.AppleAccountAPIKey) != "" {
		cfg.AppleAccountAPIKey = strings.TrimSpace(fromFile.AppleAccountAPIKey)
	}
	if rawValue, ok := raw["apple_account_keep_alive_enabled"]; ok {
		var enabled bool
		if err := json.Unmarshal(rawValue, &enabled); err != nil {
			return Config{}, err
		}
		cfg.AppleAccountKeepAliveEnabled = enabled
	}
	if fromFile.AppleAccountKeepAliveMS > 0 {
		cfg.AppleAccountKeepAliveMS = fromFile.AppleAccountKeepAliveMS
	}
	if rawValue, ok := raw["mail_watcher_enabled"]; ok {
		var enabled bool
		if err := json.Unmarshal(rawValue, &enabled); err != nil {
			return Config{}, err
		}
		cfg.MailWatcherEnabled = enabled
	}
	if fromFile.MailWatcherPollMS > 0 {
		cfg.MailWatcherPollMS = fromFile.MailWatcherPollMS
	}
	if fromFile.MailWatcherFetchLimit > 0 {
		cfg.MailWatcherFetchLimit = fromFile.MailWatcherFetchLimit
	}
	if fromFile.MailWatcherInitialFetchLimit > 0 {
		cfg.MailWatcherInitialFetchLimit = fromFile.MailWatcherInitialFetchLimit
	}
	if fromFile.MailWatcherLookbackHours > 0 {
		cfg.MailWatcherLookbackHours = fromFile.MailWatcherLookbackHours
	}
	if fromFile.MailRetentionDays > 0 {
		cfg.MailRetentionDays = fromFile.MailRetentionDays
	}
	if fromFile.MailMaxPerMailbox > 0 {
		cfg.MailMaxPerMailbox = fromFile.MailMaxPerMailbox
	}
	if fromFile.PublicFastSyncWaitMS > 0 {
		cfg.PublicFastSyncWaitMS = fromFile.PublicFastSyncWaitMS
	}
	if fromFile.PublicSyncMinIntervalMS > 0 {
		cfg.PublicSyncMinIntervalMS = fromFile.PublicSyncMinIntervalMS
	}
	if rawValue, ok := raw["update_enabled"]; ok {
		var enabled bool
		if err := json.Unmarshal(rawValue, &enabled); err != nil {
			return Config{}, err
		}
		cfg.UpdateEnabled = enabled
	}
	if strings.TrimSpace(fromFile.UpdateRepository) != "" {
		cfg.UpdateRepository = strings.TrimSpace(fromFile.UpdateRepository)
	}
	if strings.TrimSpace(fromFile.UpdateManifestURL) != "" {
		cfg.UpdateManifestURL = strings.TrimSpace(fromFile.UpdateManifestURL)
	}
	if strings.TrimSpace(fromFile.UpdateAssetName) != "" {
		cfg.UpdateAssetName = strings.TrimSpace(fromFile.UpdateAssetName)
	}
	if rawValue, ok := raw["registration_enabled"]; ok {
		if err := json.Unmarshal(rawValue, &cfg.RegistrationEnabled); err != nil {
			return Config{}, err
		}
	}
	if strings.TrimSpace(fromFile.RegistrationInviteCode) != "" {
		cfg.RegistrationInviteCode = strings.TrimSpace(fromFile.RegistrationInviteCode)
	}
	if fromFile.LoginRateLimitPerIP > 0 {
		cfg.LoginRateLimitPerIP = fromFile.LoginRateLimitPerIP
	}
	if fromFile.LoginRateLimitPerUsername > 0 {
		cfg.LoginRateLimitPerUsername = fromFile.LoginRateLimitPerUsername
	}
	if fromFile.LoginRateLimitWindowSeconds > 0 {
		cfg.LoginRateLimitWindowSeconds = fromFile.LoginRateLimitWindowSeconds
	}
	if fromFile.LoginBackoffMaxSeconds > 0 {
		cfg.LoginBackoffMaxSeconds = fromFile.LoginBackoffMaxSeconds
	}
	if rawValue, ok := raw["login_captcha_enabled"]; ok {
		if err := json.Unmarshal(rawValue, &cfg.LoginCaptchaEnabled); err != nil {
			return Config{}, err
		}
	}
	if strings.TrimSpace(fromFile.EasyProxiesURL) != "" {
		cfg.EasyProxiesURL = strings.TrimRight(strings.TrimSpace(fromFile.EasyProxiesURL), "/")
	}
	if strings.TrimSpace(fromFile.EasyProxiesHost) != "" {
		cfg.EasyProxiesHost = strings.TrimSpace(fromFile.EasyProxiesHost)
	}
	return cfg, nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func envBool(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func envPositiveInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
