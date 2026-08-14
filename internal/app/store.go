package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type FileStore struct {
	mu                    sync.Mutex
	path                  string
	dbPath                string
	state                 State
	persistedMessages     map[string]string
	needsMessageMigration bool
}

type DeleteUserResult struct {
	UserID         string `json:"user_id"`
	Username       string `json:"username"`
	Accounts       int    `json:"accounts"`
	Mailboxes      int    `json:"mailboxes"`
	Messages       int    `json:"messages"`
	ICloudSessions int    `json:"icloud_sessions"`
	WebSessions    int    `json:"web_sessions"`
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		path = filepath.Join("data", "state.json")
	}
	s := &FileStore{path: path, dbPath: strings.TrimSuffix(path, filepath.Ext(path)) + ".db", state: State{NextID: 1}, persistedMessages: make(map[string]string)}
	if err := s.openSQLite(); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if found, err := s.loadSQLiteLocked(); err != nil {
		return err
	} else if found {
		if s.state.NextID <= 0 {
			s.state.NextID = 1
		}
		if s.migrateLegacyMailboxAccountIDsLocked() || s.needsMessageMigration {
			return s.saveLocked()
		}
		return nil
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.saveLocked()
		}
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return s.saveLocked()
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return err
	}
	if s.state.NextID <= 0 {
		s.state.NextID = 1
	}
	s.migrateLegacyMailboxAccountIDsLocked()
	return s.saveLocked()
}

func (s *FileStore) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state)
}

func (s *FileStore) SnapshotForOwner(ownerID string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return filterStateByOwnerLocked(s.state, strings.TrimSpace(ownerID))
}

// SnapshotForMailboxList keeps mailbox queries small by omitting messages and
// unrelated collections. The list endpoint only needs account/session data.
func (s *FileStore) SnapshotForMailboxList(ownerID string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	ownerID = strings.TrimSpace(ownerID)
	in := s.state
	out := State{
		Accounts:       append([]Account(nil), in.Accounts...),
		Mailboxes:      append([]Mailbox(nil), in.Mailboxes...),
		ICloudSessions: make([]ICloudSession, len(in.ICloudSessions)),
	}
	if ownerID != "" {
		filteredAccounts := out.Accounts[:0]
		for _, account := range out.Accounts {
			if constantTimeEqual(account.OwnerID, ownerID) {
				filteredAccounts = append(filteredAccounts, account)
			}
		}
		out.Accounts = filteredAccounts
		filtered := out.Mailboxes[:0]
		for _, mailbox := range out.Mailboxes {
			if constantTimeEqual(mailbox.OwnerID, ownerID) {
				filtered = append(filtered, mailbox)
			}
		}
		out.Mailboxes = filtered
	}
	for i := range in.ICloudSessions {
		if ownerID == "" || constantTimeEqual(in.ICloudSessions[i].OwnerID, ownerID) {
			out.ICloudSessions[i] = cloneICloudSession(in.ICloudSessions[i])
		}
	}
	return out
}

// SnapshotForManage avoids cloning full message bodies for the compact admin
// dashboard. The dashboard needs counts and metadata, not the potentially
// very large HTML/plaintext payloads.
func (s *FileStore) SnapshotForManage() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := s.state
	out := State{
		Users: append([]User(nil), in.Users...), Accounts: append([]Account(nil), in.Accounts...),
		Mailboxes: append([]Mailbox(nil), in.Mailboxes...), ICloudSessions: make([]ICloudSession, len(in.ICloudSessions)),
		Invites: append([]InviteCode(nil), in.Invites...), InviteUses: append([]InviteUse(nil), in.InviteUses...),
		Announcements: append([]Announcement(nil), in.Announcements...), AuditEvents: append([]AuditEvent(nil), in.AuditEvents...),
		RecycleBin: append([]RecycleBinItem(nil), in.RecycleBin...),
	}
	if in.ICloudSession != nil {
		copy := cloneICloudSession(*in.ICloudSession)
		out.ICloudSession = &copy
	}
	for i := range in.ICloudSessions {
		out.ICloudSessions[i] = cloneICloudSession(in.ICloudSessions[i])
	}
	// Keep only message metadata for per-user message counts.
	out.Messages = make([]Message, len(in.Messages))
	for i, message := range in.Messages {
		out.Messages[i] = Message{ID: message.ID, OwnerID: message.OwnerID, MailboxID: message.MailboxID}
	}
	return out
}

func (s *FileStore) SnapshotForManageForOwner(ownerID string) State {
	return filterStateByOwnerLocked(s.SnapshotForManage(), strings.TrimSpace(ownerID))
}

func (s *FileStore) MailboxCountForAccount(ownerID, accountID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, mailbox := range s.state.Mailboxes {
		if constantTimeEqual(mailbox.OwnerID, ownerID) && constantTimeEqual(mailbox.AccountID, accountID) {
			count++
		}
	}
	return count
}

func (s *FileStore) MarkMailboxesAsAliases(ownerID, parentID string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[strings.TrimSpace(id)] = true
	}
	parentID = strings.TrimSpace(parentID)
	for i := range s.state.Mailboxes {
		if !wanted[s.state.Mailboxes[i].ID] || !constantTimeEqual(s.state.Mailboxes[i].OwnerID, ownerID) {
			continue
		}
		s.state.Mailboxes[i].MailboxType = "alias"
		s.state.Mailboxes[i].ParentMailboxID = parentID
		s.state.Mailboxes[i].UpdatedAt = now
	}
	return s.saveLocked()
}

// CountsForOwner returns lightweight dashboard counters without cloning the
// full state (message bodies can be large and /api/status is polled often).
func (s *FileStore) CountsForOwner(ownerID string) (accounts, mailboxes, messages int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ownerID = strings.TrimSpace(ownerID)
	for _, account := range s.state.Accounts {
		if ownerID == "" || constantTimeEqual(account.OwnerID, ownerID) {
			accounts++
		}
	}
	for _, mailbox := range s.state.Mailboxes {
		if ownerID == "" || constantTimeEqual(mailbox.OwnerID, ownerID) {
			mailboxes++
		}
	}
	for _, message := range s.state.Messages {
		if ownerID == "" || constantTimeEqual(message.OwnerID, ownerID) {
			messages++
		}
	}
	return accounts, mailboxes, messages
}

func (s *FileStore) CreateSettingsForOwner(ownerID string) CreateSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return createSettingsForOwnerLocked(s.state, strings.TrimSpace(ownerID))
}

func (s *FileStore) SaveCreateSettingsForOwner(ownerID string, settings CreateSettings) (CreateSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	settings = normalizeCreateSettings(ownerID, settings)
	settings.UpdatedAt = time.Now()
	for i := range s.state.CreateSettings {
		if constantTimeEqual(ownerID, s.state.CreateSettings[i].OwnerID) {
			s.state.CreateSettings[i] = settings
			return settings, s.saveLocked()
		}
	}
	s.state.CreateSettings = append(s.state.CreateSettings, settings)
	return settings, s.saveLocked()
}

func (s *FileStore) Users() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]User(nil), s.state.Users...)
}

func (s *FileStore) CreateAnnouncement(title, content, createdBy string) (Announcement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	title = strings.TrimSpace(title)
	content = strings.TrimSpace(content)
	if title == "" {
		return Announcement{}, errCode("announcement_title_required", "请输入公告标题", false)
	}
	if content == "" {
		return Announcement{}, errCode("announcement_content_required", "请输入公告内容", false)
	}
	if len([]rune(title)) > 100 || len([]rune(content)) > 5000 {
		return Announcement{}, errCode("announcement_too_long", "公告标题最多 100 字，内容最多 5000 字", false)
	}
	announcement := Announcement{ID: s.nextIDLocked("ann"), Title: title, Content: content, CreatedBy: strings.TrimSpace(createdBy), CreatedAt: time.Now()}
	s.state.Announcements = append(s.state.Announcements, announcement)
	return announcement, s.saveLocked()
}

func (s *FileStore) Announcements() []Announcement {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Announcement(nil), s.state.Announcements...)
}

func (s *FileStore) UnreadAnnouncements(userID string) []Announcement {
	s.mu.Lock()
	defer s.mu.Unlock()
	read := make(map[string]bool)
	for _, item := range s.state.AnnouncementReads {
		if item.UserID == userID {
			read[item.AnnouncementID] = true
		}
	}
	out := make([]Announcement, 0)
	for _, item := range s.state.Announcements {
		if !read[item.ID] {
			out = append(out, item)
		}
	}
	return out
}

func (s *FileStore) MarkAnnouncementRead(userID, announcementID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, announcementID = strings.TrimSpace(userID), strings.TrimSpace(announcementID)
	found := false
	for _, item := range s.state.Announcements {
		if item.ID == announcementID {
			found = true
			break
		}
	}
	if !found {
		return errCode("announcement_not_found", "公告不存在", false)
	}
	for _, item := range s.state.AnnouncementReads {
		if item.UserID == userID && item.AnnouncementID == announcementID {
			return nil
		}
	}
	s.state.AnnouncementReads = append(s.state.AnnouncementReads, AnnouncementRead{AnnouncementID: announcementID, UserID: userID, ReadAt: time.Now()})
	return s.saveLocked()
}

func (s *FileStore) SaveAutoLoginBinding(binding AutoLoginBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.AutoLoginBindings {
		if s.state.AutoLoginBindings[i].OwnerID == binding.OwnerID && s.state.AutoLoginBindings[i].AccountID == binding.AccountID {
			s.state.AutoLoginBindings[i] = binding
			return s.saveLocked()
		}
	}
	s.state.AutoLoginBindings = append(s.state.AutoLoginBindings, binding)
	return s.saveLocked()
}

func (s *FileStore) SetAutoLoginBindingEnabled(ownerID, accountID string, enabled bool) (AutoLoginBinding, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.AutoLoginBindings {
		binding := &s.state.AutoLoginBindings[i]
		if binding.OwnerID != ownerID || binding.AccountID != accountID {
			continue
		}
		binding.Enabled = enabled
		binding.UpdatedAt = time.Now()
		binding.LastError = ""
		binding.NextAttemptAt = time.Time{}
		if enabled {
			binding.Status = "等待登录态异常时自动登录"
		} else {
			binding.Status = "已暂停自动接码登录"
		}
		if err := s.saveLocked(); err != nil {
			return AutoLoginBinding{}, true, err
		}
		return *binding, true, nil
	}
	return AutoLoginBinding{}, false, nil
}

// SaveAutoLoginProgress updates only runtime fields and never re-enables a
// binding that was paused while an automatic login attempt was running.
func (s *FileStore) SaveAutoLoginProgress(progress AutoLoginBinding) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.AutoLoginBindings {
		binding := &s.state.AutoLoginBindings[i]
		if binding.OwnerID != progress.OwnerID || binding.AccountID != progress.AccountID {
			continue
		}
		if !binding.Enabled {
			return false, nil
		}
		binding.Status = progress.Status
		binding.LastError = progress.LastError
		binding.LastAttemptAt = progress.LastAttemptAt
		binding.LastSuccessAt = progress.LastSuccessAt
		binding.NextAttemptAt = progress.NextAttemptAt
		if err := s.saveLocked(); err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

func (s *FileStore) AutoLoginBinding(ownerID, accountID string) (AutoLoginBinding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.state.AutoLoginBindings {
		if item.OwnerID == ownerID && item.AccountID == accountID {
			return item, true
		}
	}
	return AutoLoginBinding{}, false
}

func (s *FileStore) AutoLoginBindings() []AutoLoginBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AutoLoginBinding(nil), s.state.AutoLoginBindings...)
}

func (s *FileStore) StartAutoLoginAttempt(ownerID, accountID, appleID string) (AutoLoginAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := AutoLoginAttempt{ID: s.nextIDLocked("autolog"), OwnerID: strings.TrimSpace(ownerID), AccountID: strings.TrimSpace(accountID), AppleID: strings.TrimSpace(appleID), Status: "running", StartedAt: time.Now()}
	row.Steps = append(row.Steps, AutoLoginStep{Stage: "start", Message: "自动接码登录任务开始", OK: true, At: row.StartedAt})
	s.state.AutoLoginLogs = append(s.state.AutoLoginLogs, row)
	// Each account keeps only its latest ten attempts; other accounts are untouched.
	seen := 0
	kept := make([]AutoLoginAttempt, 0, len(s.state.AutoLoginLogs))
	for i := len(s.state.AutoLoginLogs) - 1; i >= 0; i-- {
		item := s.state.AutoLoginLogs[i]
		if item.OwnerID == row.OwnerID && item.AccountID == row.AccountID {
			seen++
			if seen > 10 {
				continue
			}
		}
		kept = append(kept, item)
	}
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	s.state.AutoLoginLogs = kept
	return row, s.saveLocked()
}

func (s *FileStore) AppendAutoLoginStep(id, stage, message, code string, ok bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.AutoLoginLogs {
		if s.state.AutoLoginLogs[i].ID == id {
			s.state.AutoLoginLogs[i].Steps = append(s.state.AutoLoginLogs[i].Steps, AutoLoginStep{Stage: stage, Message: message, Code: code, OK: ok, At: time.Now()})
			return s.saveLocked()
		}
	}
	return nil
}

func (s *FileStore) FinishAutoLoginAttempt(id, status, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.AutoLoginLogs {
		if s.state.AutoLoginLogs[i].ID == id {
			s.state.AutoLoginLogs[i].Status = status
			s.state.AutoLoginLogs[i].Error = strings.TrimSpace(message)
			s.state.AutoLoginLogs[i].FinishedAt = time.Now()
			return s.saveLocked()
		}
	}
	return nil
}

func (s *FileStore) AutoLoginAttempts(ownerID, accountID string, limit int) []AutoLoginAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 10 {
		limit = 10
	}
	out := make([]AutoLoginAttempt, 0, limit)
	for i := len(s.state.AutoLoginLogs) - 1; i >= 0 && len(out) < limit; i-- {
		row := s.state.AutoLoginLogs[i]
		if row.OwnerID == ownerID && row.AccountID == accountID {
			row.Steps = append([]AutoLoginStep(nil), row.Steps...)
			out = append(out, row)
		}
	}
	return out
}

func (s *FileStore) SaveUserProxyConfig(config UserProxyConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.UserProxyConfigs {
		if constantTimeEqual(s.state.UserProxyConfigs[i].OwnerID, config.OwnerID) {
			s.state.UserProxyConfigs[i] = config
			return s.saveLocked()
		}
	}
	s.state.UserProxyConfigs = append(s.state.UserProxyConfigs, config)
	return s.saveLocked()
}

func (s *FileStore) UserProxyConfig(ownerID string) (UserProxyConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, config := range s.state.UserProxyConfigs {
		if constantTimeEqual(config.OwnerID, ownerID) {
			config.PoolNodes = append([]ProxyPoolNode(nil), config.PoolNodes...)
			return config, true
		}
	}
	return UserProxyConfig{}, false
}

func (s *FileStore) SaveAccountProxyPoolNode(ownerID, accountID, node string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ownerID, accountID, node = strings.TrimSpace(ownerID), strings.TrimSpace(accountID), strings.TrimSpace(node)
	for i := range s.state.Accounts {
		if constantTimeEqual(s.state.Accounts[i].OwnerID, ownerID) && constantTimeEqual(s.state.Accounts[i].ID, accountID) {
			s.state.Accounts[i].ProxyPoolNode = node
			s.state.Accounts[i].UpdatedAt = time.Now()
			for j := range s.state.ICloudSessions {
				if s.state.ICloudSessions[j].OwnerID == ownerID && s.state.ICloudSessions[j].AccountID == accountID {
					s.state.ICloudSessions[j].ProxyNodeTag = node
					s.state.ICloudSessions[j].ProxyNodeName = node
				}
			}
			return s.saveLocked()
		}
	}
	return errCode("account_not_found", "账号不存在", false)
}

func (s *FileStore) ProxyPoolNodeForAccount(ownerID, accountID, appleID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, account := range s.state.Accounts {
		if !constantTimeEqual(account.OwnerID, strings.TrimSpace(ownerID)) {
			continue
		}
		if strings.TrimSpace(accountID) != "" && constantTimeEqual(account.ID, strings.TrimSpace(accountID)) {
			return strings.TrimSpace(account.ProxyPoolNode)
		}
		if strings.TrimSpace(appleID) != "" && strings.EqualFold(strings.TrimSpace(account.AppleID), strings.TrimSpace(appleID)) {
			return strings.TrimSpace(account.ProxyPoolNode)
		}
	}
	return ""
}

func (s *FileStore) SaveProxyPoolNodeResult(ownerID, nodeName string, result ProxyPoolNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ownerID, nodeName = strings.TrimSpace(ownerID), strings.TrimSpace(nodeName)
	for i := range s.state.UserProxyConfigs {
		config := &s.state.UserProxyConfigs[i]
		if !constantTimeEqual(config.OwnerID, ownerID) {
			continue
		}
		for j := range config.PoolNodes {
			if config.PoolNodes[j].Name == nodeName {
				config.PoolNodes[j].Available = result.Available
				config.PoolNodes[j].LatencyMS = result.LatencyMS
				config.PoolNodes[j].ExitIP = result.ExitIP
				config.PoolNodes[j].TLSOK = result.TLSOK
				config.PoolNodes[j].LastError = result.LastError
				config.PoolNodes[j].LastTestedAt = result.LastTestedAt
				return s.saveLocked()
			}
		}
		return errCode("proxy_pool_node_missing", "代理池节点不存在", false)
	}
	return errCode("proxy_pool_missing", "代理池配置不存在", false)
}

func (s *FileStore) CreateUser(username, password string) (User, error) {
	return s.createUser(username, password, false)
}

func (s *FileStore) CreateUserByAdmin(username, password string, expiresAt time.Time) (User, error) {
	user, err := s.createUser(username, password, true)
	if err != nil {
		return User{}, err
	}
	return s.UpdateUserExpiry(user.ID, expiresAt)
}

func (s *FileStore) createUser(username, password string, forceNormalUser bool) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username = normalizeUsername(username)
	if err := validateUsername(username); err != nil {
		return User{}, err
	}
	if err := validatePassword(password); err != nil {
		return User{}, err
	}
	for _, user := range s.state.Users {
		if strings.EqualFold(user.Username, username) {
			return User{}, errCode("user_exists", "账号已存在", false)
		}
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	now := time.Now()
	user := User{
		ID:           s.nextIDLocked("usr"),
		Username:     username,
		PasswordHash: passwordHash,
		IsAdmin:      !forceNormalUser && len(s.state.Users) == 0,
		Status:       StatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.state.Users = append(s.state.Users, user)
	return user, s.saveLocked()
}

func (s *FileStore) UpdateUserExpiry(id string, expiresAt time.Time) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Users {
		if s.state.Users[i].ID != strings.TrimSpace(id) {
			continue
		}
		if s.state.Users[i].IsAdmin {
			return User{}, errCode("cannot_expire_admin", "管理员账号不设置到期时间", false)
		}
		s.state.Users[i].ExpiresAt = expiresAt
		s.state.Users[i].UpdatedAt = time.Now()
		return s.state.Users[i], s.saveLocked()
	}
	return User{}, errCode("user_not_found", "账号不存在", false)
}

func (s *FileStore) InactiveUserIDs(cutoff time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for _, user := range s.state.Users {
		if user.IsAdmin {
			continue
		}
		lastUsed := user.LastLoginAt
		if lastUsed.IsZero() {
			lastUsed = user.CreatedAt
		}
		if !lastUsed.IsZero() && lastUsed.Before(cutoff) {
			ids = append(ids, user.ID)
		}
	}
	return ids
}

func (s *FileStore) CreateInvite(name, createdBy string, maxUses int, expiresAt time.Time) (InviteCode, string, error) {
	validDays := 0
	if !expiresAt.IsZero() {
		validDays = max(1, int(time.Until(expiresAt).Hours()/24+.999))
	}
	invites, codes, err := s.CreateInvites(name, createdBy, 1, maxUses, validDays)
	if err != nil {
		return InviteCode{}, "", err
	}
	return invites[0], codes[0], nil
}

func (s *FileStore) CreateInvites(name, createdBy string, count, maxUses, validDays int) ([]InviteCode, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil, errCode("invite_name_required", "请输入邀请码名称", false)
	}
	if maxUses < 1 {
		maxUses = 1
	}
	if maxUses > 10000 {
		maxUses = 10000
	}
	if count < 1 {
		count = 1
	}
	if count > 1000 {
		count = 1000
	}
	if validDays < 1 {
		validDays = 30
	}
	if validDays > 3650 {
		validDays = 3650
	}
	invites := make([]InviteCode, 0, count)
	codes := make([]string, 0, count)
	for index := 0; index < count; index++ {
		raw, err := randomToken(24)
		if err != nil {
			return nil, nil, err
		}
		now := time.Now()
		inviteName := name
		if count > 1 {
			inviteName = fmt.Sprintf("%s-%03d", name, index+1)
		}
		invite := InviteCode{ID: s.nextIDLocked("inv"), CodeHash: sessionTokenHash(raw), Code: raw, Name: inviteName, CreatedBy: createdBy, Role: "user", MaxUses: maxUses, ValidDays: validDays, Enabled: true, CreatedAt: now}
		s.state.Invites = append(s.state.Invites, invite)
		invites = append(invites, invite)
		codes = append(codes, raw)
	}
	return invites, codes, s.saveLocked()
}

func (s *FileStore) RedeemInvite(raw, userID, ip string) (InviteCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := sessionTokenHash(raw)
	now := time.Now()
	for i := range s.state.Invites {
		invite := &s.state.Invites[i]
		if !constantTimeEqual(hash, invite.CodeHash) {
			continue
		}
		if !invite.Enabled {
			return InviteCode{}, errCode("invite_disabled", "邀请码已禁用", false)
		}
		if !invite.ExpiresAt.IsZero() && !invite.ExpiresAt.After(now) {
			return InviteCode{}, errCode("invite_expired", "邀请码已过期", false)
		}
		if invite.UsedCount >= invite.MaxUses {
			return InviteCode{}, errCode("invite_exhausted", "邀请码使用次数已满", false)
		}
		for _, use := range s.state.InviteUses {
			if use.InviteID == invite.ID && use.UserID == userID {
				return InviteCode{}, errCode("invite_already_used", "该账号已经使用过这个邀请码，请更换未使用的邀请码", false)
			}
		}
		invite.UsedCount++
		if invite.ValidDays <= 0 {
			invite.ValidDays = 30
		}
		renewBase := now
		for _, user := range s.state.Users {
			if user.ID == userID && user.ExpiresAt.After(renewBase) {
				renewBase = user.ExpiresAt
				break
			}
		}
		invite.ExpiresAt = renewBase.AddDate(0, 0, invite.ValidDays)
		s.state.InviteUses = append(s.state.InviteUses, InviteUse{InviteID: invite.ID, UserID: userID, RegisteredIP: ip, RedeemedAt: now})
		for u := range s.state.Users {
			if s.state.Users[u].ID == userID {
				s.state.Users[u].InvitedBy = invite.CreatedBy
				s.state.Users[u].InviteID = invite.ID
				s.state.Users[u].ExpiresAt = invite.ExpiresAt
			}
		}
		return *invite, s.saveLocked()
	}
	return InviteCode{}, errCode("invalid_invite_code", "邀请码无效", false)
}

func (s *FileStore) ValidateInvite(raw string) (InviteCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, now := sessionTokenHash(raw), time.Now()
	for _, invite := range s.state.Invites {
		if !constantTimeEqual(hash, invite.CodeHash) {
			continue
		}
		if !invite.Enabled {
			return InviteCode{}, errCode("invite_disabled", "邀请码已禁用", false)
		}
		if !invite.ExpiresAt.IsZero() && !invite.ExpiresAt.After(now) {
			return InviteCode{}, errCode("invite_expired", "邀请码已过期", false)
		}
		if invite.UsedCount >= invite.MaxUses {
			return InviteCode{}, errCode("invite_exhausted", "邀请码使用次数已满", false)
		}
		return invite, nil
	}
	return InviteCode{}, errCode("invalid_invite_code", "邀请码无效", false)
}

func (s *FileStore) SetInviteEnabled(id string, enabled bool) (InviteCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Invites {
		if s.state.Invites[i].ID == id {
			s.state.Invites[i].Enabled = enabled
			return s.state.Invites[i], s.saveLocked()
		}
	}
	return InviteCode{}, errCode("invite_not_found", "邀请码不存在", false)
}

func (s *FileStore) UpdateAccountMetadata(id, category string, tags []string, actorID string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	category = strings.TrimSpace(category)
	if len(category) > 32 {
		return Account{}, errCode("invalid_category", "账号分类过长", false)
	}
	normalized := make([]string, 0, len(tags))
	seen := map[string]bool{}
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag != "" && len(tag) <= 24 && !seen[tag] && len(normalized) < 12 {
			seen[tag] = true
			normalized = append(normalized, tag)
		}
	}
	for i := range s.state.Accounts {
		if s.state.Accounts[i].ID == id {
			s.state.Accounts[i].Category = category
			s.state.Accounts[i].Tags = normalized
			s.state.Accounts[i].AssignedBy = actorID
			s.state.Accounts[i].UpdatedAt = time.Now()
			return s.state.Accounts[i], s.saveLocked()
		}
	}
	return Account{}, errCode("account_not_found", "Apple 账号不存在", false)
}

func (s *FileStore) AddAuditEvent(event AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.ID = s.nextIDLocked("aud")
	event.CreatedAt = time.Now()
	s.state.AuditEvents = append(s.state.AuditEvents, event)
	if len(s.state.AuditEvents) > 1000 {
		s.state.AuditEvents = append([]AuditEvent(nil), s.state.AuditEvents[len(s.state.AuditEvents)-1000:]...)
	}
	_ = s.saveLocked()
}

func (s *FileStore) AuthenticateUser(username, password string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username = normalizeUsername(username)
	for i, user := range s.state.Users {
		if !strings.EqualFold(user.Username, username) {
			continue
		}
		if user.Status != StatusActive {
			return User{}, errCode("user_disabled", "账号已停用", false)
		}
		if !verifyPassword(password, user.PasswordHash) {
			return User{}, errCode("invalid_login", "账号或密码错误", false)
		}
		now := time.Now()
		if !strings.HasPrefix(user.PasswordHash, passwordHashVersion+"$") {
			if upgraded, upgradeErr := hashPassword(password); upgradeErr == nil {
				s.state.Users[i].PasswordHash = upgraded
			}
		}
		s.state.Users[i].LastLoginAt = now
		s.state.Users[i].UpdatedAt = now
		return s.state.Users[i], s.saveLocked()
	}
	return User{}, errCode("invalid_login", "账号或密码错误", false)
}

func (s *FileStore) ChangePassword(userID, currentPassword, newPassword, keepToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	for i := range s.state.Users {
		if s.state.Users[i].ID != userID {
			continue
		}
		if !verifyPassword(currentPassword, s.state.Users[i].PasswordHash) {
			return errCode("invalid_current_password", "当前密码错误", false)
		}
		hash, err := hashPassword(newPassword)
		if err != nil {
			return err
		}
		s.state.Users[i].PasswordHash = hash
		s.state.Users[i].UpdatedAt = time.Now()
		keepHash := sessionTokenHash(keepToken)
		filtered := s.state.WebSessions[:0]
		for _, session := range s.state.WebSessions {
			if session.UserID != userID || constantTimeEqual(session.TokenHash, keepHash) {
				filtered = append(filtered, session)
			}
		}
		s.state.WebSessions = filtered
		return s.saveLocked()
	}
	return errCode("user_not_found", "账号不存在", false)
}

func (s *FileStore) VerifyUserPassword(userID, password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.state.Users {
		if user.ID == strings.TrimSpace(userID) {
			return verifyPassword(password, user.PasswordHash)
		}
	}
	return false
}

func (s *FileStore) UserByID(id string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userByIDLocked(id)
}

func (s *FileStore) DeleteUser(id string) (DeleteUserResult, error) {
	return s.DeleteUserWithReason(id, "管理员删除")
}

func (s *FileStore) DeleteUserWithReason(id, reason string) (DeleteUserResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return DeleteUserResult{}, errCode("user_not_found", "账号不存在", false)
	}
	idx := -1
	var user User
	for i, candidate := range s.state.Users {
		if candidate.ID == id {
			idx = i
			user = candidate
			break
		}
	}
	if idx < 0 {
		return DeleteUserResult{}, errCode("user_not_found", "账号不存在", false)
	}
	if user.IsAdmin {
		return DeleteUserResult{}, errCode("cannot_delete_admin_user", "不能删除管理员账号", false)
	}
	recycleState := filterStateByOwnerLocked(s.state, id)
	for _, item := range s.state.InviteUses {
		if item.UserID == id {
			recycleState.InviteUses = append(recycleState.InviteUses, item)
		}
	}
	for _, item := range s.state.AnnouncementReads {
		if item.UserID == id {
			recycleState.AnnouncementReads = append(recycleState.AnnouncementReads, item)
		}
	}
	for _, item := range s.state.AutoLoginBindings {
		if item.OwnerID == id {
			recycleState.AutoLoginBindings = append(recycleState.AutoLoginBindings, item)
		}
	}
	recycleData, err := json.Marshal(recycleState)
	if err != nil {
		return DeleteUserResult{}, err
	}
	now := time.Now()
	s.state.RecycleBin = append(s.state.RecycleBin, RecycleBinItem{ID: s.nextIDLocked("trash"), UserID: id, Username: user.Username, Reason: strings.TrimSpace(reason), Data: recycleData, DeletedAt: now, PurgeAt: now.Add(7 * 24 * time.Hour)})

	result := DeleteUserResult{
		UserID:   user.ID,
		Username: user.Username,
	}
	s.state.Users = append(s.state.Users[:idx], s.state.Users[idx+1:]...)

	accounts := s.state.Accounts[:0]
	for _, account := range s.state.Accounts {
		if constantTimeEqual(id, account.OwnerID) {
			result.Accounts++
			continue
		}
		accounts = append(accounts, account)
	}
	s.state.Accounts = accounts

	deletedMailboxIDs := make(map[string]struct{})
	mailboxes := s.state.Mailboxes[:0]
	for _, mailbox := range s.state.Mailboxes {
		if constantTimeEqual(id, mailbox.OwnerID) {
			result.Mailboxes++
			deletedMailboxIDs[mailbox.ID] = struct{}{}
			continue
		}
		mailboxes = append(mailboxes, mailbox)
	}
	s.state.Mailboxes = mailboxes

	messages := s.state.Messages[:0]
	for _, msg := range s.state.Messages {
		_, mailboxDeleted := deletedMailboxIDs[msg.MailboxID]
		if mailboxDeleted || constantTimeEqual(id, msg.OwnerID) {
			result.Messages++
			continue
		}
		messages = append(messages, msg)
	}
	s.state.Messages = messages

	icloudSessions := s.state.ICloudSessions[:0]
	for _, session := range s.state.ICloudSessions {
		if constantTimeEqual(id, session.OwnerID) {
			result.ICloudSessions++
			continue
		}
		icloudSessions = append(icloudSessions, session)
	}
	s.state.ICloudSessions = icloudSessions

	webSessions := s.state.WebSessions[:0]
	for _, session := range s.state.WebSessions {
		if constantTimeEqual(id, session.UserID) {
			result.WebSessions++
			continue
		}
		webSessions = append(webSessions, session)
	}
	s.state.WebSessions = webSessions

	createSettings := s.state.CreateSettings[:0]
	for _, item := range s.state.CreateSettings {
		if item.OwnerID != id {
			createSettings = append(createSettings, item)
		}
	}
	s.state.CreateSettings = createSettings
	inviteUses := s.state.InviteUses[:0]
	for _, item := range s.state.InviteUses {
		if item.UserID != id {
			inviteUses = append(inviteUses, item)
		}
	}
	s.state.InviteUses = inviteUses
	announcementReads := s.state.AnnouncementReads[:0]
	for _, item := range s.state.AnnouncementReads {
		if item.UserID != id {
			announcementReads = append(announcementReads, item)
		}
	}
	s.state.AnnouncementReads = announcementReads
	autoLoginBindings := s.state.AutoLoginBindings[:0]
	for _, item := range s.state.AutoLoginBindings {
		if item.OwnerID != id {
			autoLoginBindings = append(autoLoginBindings, item)
		}
	}
	s.state.AutoLoginBindings = autoLoginBindings
	proxyConfigs := s.state.UserProxyConfigs[:0]
	for _, item := range s.state.UserProxyConfigs {
		if item.OwnerID != id {
			proxyConfigs = append(proxyConfigs, item)
		}
	}
	s.state.UserProxyConfigs = proxyConfigs
	redemptionPools := s.state.RedemptionPools[:0]
	for _, item := range s.state.RedemptionPools {
		if item.OwnerID != id {
			redemptionPools = append(redemptionPools, item)
		}
	}
	s.state.RedemptionPools = redemptionPools
	redemptionCodes := s.state.RedemptionCodes[:0]
	for _, item := range s.state.RedemptionCodes {
		if item.OwnerID != id {
			redemptionCodes = append(redemptionCodes, item)
		}
	}
	s.state.RedemptionCodes = redemptionCodes
	redemptionItems := s.state.RedemptionItems[:0]
	for _, item := range s.state.RedemptionItems {
		if item.OwnerID != id {
			redemptionItems = append(redemptionItems, item)
		}
	}
	s.state.RedemptionItems = redemptionItems

	return result, s.saveLocked()
}

func (s *FileStore) RecycleBin() []RecycleBinItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]RecycleBinItem(nil), s.state.RecycleBin...)
	for i := range out {
		out[i].Data = nil
	}
	return out
}

func (s *FileStore) RestoreUserFromRecycleBin(itemID string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i := range s.state.RecycleBin {
		if s.state.RecycleBin[i].ID == strings.TrimSpace(itemID) {
			index = i
			break
		}
	}
	if index < 0 {
		return User{}, errCode("recycle_item_not_found", "回收站记录不存在", false)
	}
	item := s.state.RecycleBin[index]
	var restored State
	if err := json.Unmarshal(item.Data, &restored); err != nil {
		return User{}, err
	}
	if len(restored.Users) != 1 {
		return User{}, errCode("invalid_recycle_data", "回收站用户数据不完整", false)
	}
	for _, existing := range s.state.Users {
		if existing.ID == restored.Users[0].ID || strings.EqualFold(existing.Username, restored.Users[0].Username) {
			return User{}, errCode("user_exists", "同名账号或用户ID已存在，无法恢复", false)
		}
	}
	s.state.Users = append(s.state.Users, restored.Users...)
	s.state.Accounts = append(s.state.Accounts, restored.Accounts...)
	s.state.Mailboxes = append(s.state.Mailboxes, restored.Mailboxes...)
	s.state.Messages = append(s.state.Messages, restored.Messages...)
	s.state.ICloudSessions = append(s.state.ICloudSessions, restored.ICloudSessions...)
	s.state.CreateSettings = append(s.state.CreateSettings, restored.CreateSettings...)
	s.state.InviteUses = append(s.state.InviteUses, restored.InviteUses...)
	s.state.AnnouncementReads = append(s.state.AnnouncementReads, restored.AnnouncementReads...)
	s.state.AutoLoginBindings = append(s.state.AutoLoginBindings, restored.AutoLoginBindings...)
	s.state.RedemptionPools = append(s.state.RedemptionPools, restored.RedemptionPools...)
	s.state.RedemptionCodes = append(s.state.RedemptionCodes, restored.RedemptionCodes...)
	s.state.RedemptionItems = append(s.state.RedemptionItems, restored.RedemptionItems...)
	s.state.RecycleBin = append(s.state.RecycleBin[:index], s.state.RecycleBin[index+1:]...)
	return restored.Users[0], s.saveLocked()
}

func (s *FileStore) PurgeExpiredRecycleBin(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.state.RecycleBin[:0]
	purged := 0
	for _, item := range s.state.RecycleBin {
		if !item.PurgeAt.IsZero() && !item.PurgeAt.After(now) {
			purged++
			continue
		}
		kept = append(kept, item)
	}
	s.state.RecycleBin = kept
	if purged > 0 {
		_ = s.saveLocked()
	}
	return purged
}

func (s *FileStore) CreateWebSession(userID string, isAdmin bool, ttl time.Duration) (string, WebSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID = strings.TrimSpace(userID)
	if _, ok := s.userByIDLocked(userID); !ok {
		return "", WebSession{}, errCode("user_not_found", "账号不存在", false)
	}
	token, err := randomToken(32)
	if err != nil {
		return "", WebSession{}, err
	}
	now := time.Now()
	session := WebSession{
		TokenHash:  sessionTokenHash(token),
		UserID:     userID,
		IsAdmin:    isAdmin,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(ttl),
	}
	s.state.WebSessions = append(s.state.WebSessions, session)
	return token, session, s.saveLocked()
}

func (s *FileStore) WebSessionByToken(token string) (WebSession, User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokenHash := sessionTokenHash(token)
	if strings.TrimSpace(token) == "" {
		return WebSession{}, User{}, false
	}
	now := time.Now()
	for _, session := range s.state.WebSessions {
		if !constantTimeEqual(tokenHash, session.TokenHash) || !session.ExpiresAt.After(now) {
			continue
		}
		user, ok := s.userByIDLocked(session.UserID)
		if !ok || user.Status != StatusActive {
			return WebSession{}, User{}, false
		}
		return session, user, true
	}
	return WebSession{}, User{}, false
}

func (s *FileStore) DeleteWebSession(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokenHash := sessionTokenHash(token)
	filtered := s.state.WebSessions[:0]
	for _, session := range s.state.WebSessions {
		if constantTimeEqual(tokenHash, session.TokenHash) {
			continue
		}
		filtered = append(filtered, session)
	}
	s.state.WebSessions = filtered
	return s.saveLocked()
}

func (s *FileStore) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

func (s *FileStore) SetPath(path string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path = strings.TrimSpace(path)
	if path == "" {
		path = filepath.Join("data", "state.json")
	}
	if strings.EqualFold(filepath.Ext(path), ".json") {
		path = filepath.Clean(path)
	} else {
		path = filepath.Join(path, "state.json")
	}
	s.dbPath = strings.TrimSuffix(path, filepath.Ext(path)) + ".db"
	s.persistedMessages = make(map[string]string)
	s.needsMessageMigration = false
	if err := s.openSQLite(); err != nil {
		return State{}, err
	}
	if found, err := s.loadSQLiteLocked(); err != nil {
		return State{}, err
	} else if found {
		s.path = path
		return cloneState(s.state), nil
	}
	current := cloneState(s.state)
	data, err := os.ReadFile(path)
	switch {
	case err == nil && len(strings.TrimSpace(string(data))) > 0:
		var next State
		if err := json.Unmarshal(data, &next); err != nil {
			return State{}, err
		}
		if next.NextID <= 0 {
			next.NextID = 1
		}
		s.state = next
	case err == nil:
		s.state = current
	case errors.Is(err, os.ErrNotExist):
		s.state = current
	default:
		return State{}, err
	}
	s.path = path
	if err := s.saveLocked(); err != nil {
		return State{}, err
	}
	return cloneState(s.state), nil
}

func (s *FileStore) AddAccount(label, appleID, note string) (Account, error) {
	return s.AddAccountForOwner("", label, appleID, note)
}

func (s *FileStore) AddAccountForOwner(ownerID, label, appleID, note string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	account := Account{
		ID:              s.nextIDLocked("acc"),
		OwnerID:         strings.TrimSpace(ownerID),
		CreatedBy:       strings.TrimSpace(ownerID),
		AssignedBy:      strings.TrimSpace(ownerID),
		Category:        "未分类",
		Label:           strings.TrimSpace(label),
		AppleID:         strings.TrimSpace(appleID),
		LoginIdentifier: normalizeAppleLoginIdentifier(appleID),
		Status:          StatusActive,
		ICloudStatus:    ICloudStatusNeedLogin,
		Note:            strings.TrimSpace(note),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if account.Label == "" {
		account.Label = account.ID
	}
	s.state.Accounts = append(s.state.Accounts, account)
	return account, s.saveLocked()
}

func (s *FileStore) AddMailbox(accountID, label, email string) (Mailbox, error) {
	return s.AddMailboxForOwner("", accountID, label, email)
}

func (s *FileStore) AddMailboxForOwner(ownerID, accountID, label, email string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return Mailbox{}, errCode("provider_not_configured", "当前 MVP 需要先手动填入已创建的隐私邮箱；自动创建接口留给后续 iCloud Provider 接入", false)
	}
	for _, mailbox := range s.state.Mailboxes {
		if strings.EqualFold(mailbox.Email, email) {
			return Mailbox{}, errCode("mailbox_exists", "邮箱已存在", false)
		}
	}

	now := time.Now()
	token, err := randomToken(24)
	if err != nil {
		return Mailbox{}, err
	}
	if strings.TrimSpace(label) == "" {
		label = fmt.Sprintf("UPI-%s", time.Now().Format("0102-150405"))
	}
	mailbox := Mailbox{
		ID:                s.nextIDLocked("mbx"),
		OwnerID:           strings.TrimSpace(ownerID),
		AccountID:         strings.TrimSpace(accountID),
		Label:             strings.TrimSpace(label),
		Email:             email,
		APIToken:          token,
		APITokenExpiresAt: now.Add(180 * 24 * time.Hour),
		APIActive:         true,
		ICloudActive:      true,
		Status:            StatusAvailable,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.state.Mailboxes = append(s.state.Mailboxes, mailbox)
	return mailbox, s.saveLocked()
}

func (s *FileStore) UpsertMailboxFromRemote(ownerID, accountID string, remote ICloudRemoteMailbox, defaultNote string) (Mailbox, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	email := strings.ToLower(strings.TrimSpace(remote.Email))
	if email == "" {
		return Mailbox{}, false, errCode("mailbox_email_missing", "iCloud 返回的邮箱地址为空", false)
	}
	now := time.Now()
	for i, mailbox := range s.state.Mailboxes {
		if !strings.EqualFold(mailbox.Email, email) {
			continue
		}
		if strings.TrimSpace(mailbox.OwnerID) != ownerID {
			return Mailbox{}, false, errCode("mailbox_exists_other_owner", "邮箱已存在于其他登录账号的数据中，已跳过导入", false)
		}
		if strings.TrimSpace(remote.Label) != "" {
			s.state.Mailboxes[i].Label = strings.TrimSpace(remote.Label)
		}
		if accountID != "" && strings.TrimSpace(s.state.Mailboxes[i].AccountID) != accountID {
			s.state.Mailboxes[i].AccountID = accountID
		}
		s.state.Mailboxes[i].ICloudActive = remote.IsActive
		note := strings.TrimSpace(remote.Note)
		if note == "" {
			note = strings.TrimSpace(defaultNote)
		}
		if note != "" && strings.TrimSpace(s.state.Mailboxes[i].Note) == "" {
			s.state.Mailboxes[i].Note = note
		}
		s.state.Mailboxes[i].UpdatedAt = now
		return s.state.Mailboxes[i], false, s.saveLocked()
	}

	token, err := randomToken(24)
	if err != nil {
		return Mailbox{}, false, err
	}
	label := strings.TrimSpace(remote.Label)
	if label == "" {
		label = fmt.Sprintf("HME-%s", now.Format("0102-150405"))
	}
	note := strings.TrimSpace(remote.Note)
	if note == "" {
		note = strings.TrimSpace(defaultNote)
	}
	status := StatusAvailable
	if !remote.IsActive {
		status = StatusDisabled
	}
	mailbox := Mailbox{
		ID:                s.nextIDLocked("mbx"),
		OwnerID:           ownerID,
		AccountID:         accountID,
		Label:             label,
		Email:             email,
		APIToken:          token,
		APITokenExpiresAt: now.Add(180 * 24 * time.Hour),
		APIActive:         true,
		ICloudActive:      remote.IsActive,
		Status:            status,
		Note:              note,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.state.Mailboxes = append(s.state.Mailboxes, mailbox)
	return mailbox, true, s.saveLocked()
}

func (s *FileStore) ClaimAvailableMailbox(note string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, mailbox := range s.state.Mailboxes {
		if !mailbox.APIActive || !mailbox.ICloudActive || mailbox.Status != StatusAvailable {
			continue
		}
		s.state.Mailboxes[i].Status = StatusUsed
		if strings.TrimSpace(note) != "" {
			s.state.Mailboxes[i].Note = strings.TrimSpace(note)
		}
		s.state.Mailboxes[i].UpdatedAt = time.Now()
		return s.state.Mailboxes[i], s.saveLocked()
	}
	return Mailbox{}, errCode("no_available_mailbox", "没有可用隐私邮箱", false)
}

func (s *FileStore) SaveICloudSession(session ICloudSession) error {
	return s.SaveICloudSessionForOwner("", session)
}

func (s *FileStore) SaveICloudSessionForOwner(ownerID string, session ICloudSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	session.OwnerID = ownerID
	if session.SavedAt.IsZero() {
		session.SavedAt = time.Now()
	}
	if ownerID != "" {
		if strings.TrimSpace(session.AccountID) == "" {
			session.AccountID = s.ensureICloudAccountLocked(ownerID, session)
		} else {
			s.touchICloudAccountLocked(ownerID, session.AccountID, session)
		}
		for i, existing := range s.state.ICloudSessions {
			if constantTimeEqual(ownerID, existing.OwnerID) && sameICloudSessionIdentity(existing, session) {
				merged := mergeICloudSession(existing, session)
				s.state.ICloudSessions[i] = merged
				if strings.TrimSpace(merged.AccountID) != "" {
					s.touchICloudAccountLocked(ownerID, merged.AccountID, merged)
				}
				s.pruneDuplicateIMAPOnlySessionsLocked(ownerID, merged, i)
				return s.saveLocked()
			}
		}
		s.state.ICloudSessions = append(s.state.ICloudSessions, session)
		s.pruneDuplicateIMAPOnlySessionsLocked(ownerID, session, len(s.state.ICloudSessions)-1)
		return s.saveLocked()
	}
	if s.state.ICloudSession != nil && sameICloudSessionIdentity(*s.state.ICloudSession, session) {
		session = mergeICloudSession(*s.state.ICloudSession, session)
	}
	s.state.ICloudSession = &session
	return s.saveLocked()
}

func (s *FileStore) ICloudSession() (ICloudSession, bool) {
	return s.ICloudSessionForOwner("")
}

func (s *FileStore) ICloudSessionForOwner(ownerID string) (ICloudSession, bool) {
	sessions := s.ICloudSessionsForOwner(ownerID)
	if len(sessions) == 0 {
		return ICloudSession{}, false
	}
	return sessions[0], true
}

func (s *FileStore) ICloudSessionsForOwner(ownerID string) []ICloudSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	if ownerID != "" {
		out := make([]ICloudSession, 0, 2)
		for _, session := range s.state.ICloudSessions {
			if constantTimeEqual(ownerID, session.OwnerID) {
				out = append(out, cloneICloudSession(session))
			}
		}
		return out
	}
	out := make([]ICloudSession, 0, len(s.state.ICloudSessions)+1)
	if s.state.ICloudSession != nil {
		out = append(out, cloneICloudSession(*s.state.ICloudSession))
	}
	for _, session := range s.state.ICloudSessions {
		if strings.TrimSpace(session.OwnerID) == "" {
			out = append(out, cloneICloudSession(session))
		}
	}
	return out
}

func (s *FileStore) ICloudSessionForOwnerAccount(ownerID, accountID string) (ICloudSession, bool) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return s.ICloudSessionForOwner(ownerID)
	}
	for _, session := range s.ICloudSessionsForOwner(ownerID) {
		if constantTimeEqual(accountID, session.AccountID) {
			return session, true
		}
	}
	return ICloudSession{}, false
}

func (s *FileStore) DeleteICloudSessionForOwner(ownerID, accountID string) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ownerID, accountID = strings.TrimSpace(ownerID), strings.TrimSpace(accountID)
	if ownerID == "" || accountID == "" {
		return 0, false, errCode("account_required", "请选择需要删除的登录态账号", false)
	}
	original := cloneState(s.state)
	removed := 0
	nextSessions := s.state.ICloudSessions[:0]
	for _, session := range s.state.ICloudSessions {
		if constantTimeEqual(session.OwnerID, ownerID) && constantTimeEqual(session.AccountID, accountID) {
			removed++
			continue
		}
		nextSessions = append(nextSessions, session)
	}
	if removed == 0 {
		return 0, false, errCode("icloud_session_missing", "登录态账号不存在或无权删除", false)
	}
	s.state.ICloudSessions = nextSessions
	accountIDs := map[string]struct{}{accountID: {}}
	s.removeAccountIDsFromCreateSettingsLocked(ownerID, accountIDs)
	nextBindings := s.state.AutoLoginBindings[:0]
	for _, binding := range s.state.AutoLoginBindings {
		if constantTimeEqual(binding.OwnerID, ownerID) && constantTimeEqual(binding.AccountID, accountID) {
			continue
		}
		nextBindings = append(nextBindings, binding)
	}
	s.state.AutoLoginBindings = nextBindings
	preservedMailboxes := false
	for _, mailbox := range s.state.Mailboxes {
		if constantTimeEqual(mailbox.OwnerID, ownerID) && constantTimeEqual(mailbox.AccountID, accountID) {
			preservedMailboxes = true
			break
		}
	}
	nextAccounts := s.state.Accounts[:0]
	for _, account := range s.state.Accounts {
		if constantTimeEqual(account.OwnerID, ownerID) && constantTimeEqual(account.ID, accountID) {
			if preservedMailboxes {
				account.ICloudStatus = ICloudStatusNeedLogin
				account.UpdatedAt = time.Now()
				nextAccounts = append(nextAccounts, account)
			}
			continue
		}
		nextAccounts = append(nextAccounts, account)
	}
	s.state.Accounts = nextAccounts
	if err := s.saveLocked(); err != nil {
		s.state = original
		return 0, false, err
	}
	return removed, preservedMailboxes, nil
}

func (s *FileStore) SetICloudSessionProxy(ownerID, accountID, nodeTag, nodeName string) (ICloudSession, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ownerID, accountID = strings.TrimSpace(ownerID), strings.TrimSpace(accountID)
	for i := range s.state.ICloudSessions {
		if constantTimeEqual(s.state.ICloudSessions[i].OwnerID, ownerID) && constantTimeEqual(s.state.ICloudSessions[i].AccountID, accountID) {
			s.state.ICloudSessions[i].ProxyNodeTag = strings.TrimSpace(nodeTag)
			s.state.ICloudSessions[i].ProxyNodeName = strings.TrimSpace(nodeName)
			out := cloneICloudSession(s.state.ICloudSessions[i])
			return out, true, s.saveLocked()
		}
	}
	return ICloudSession{}, false, nil
}

func (s *FileStore) FindAccountByID(id string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	for _, account := range s.state.Accounts {
		if account.ID == id {
			return account, true
		}
	}
	return Account{}, false
}

func (s *FileStore) AddMessage(mailboxID, subject, from, body string, receivedAt time.Time) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(mailboxID)
	if idx < 0 {
		return Message{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	msg := Message{
		ID:         s.nextIDLocked("msg"),
		OwnerID:    s.state.Mailboxes[idx].OwnerID,
		MailboxID:  mailboxID,
		Subject:    strings.TrimSpace(subject),
		From:       strings.TrimSpace(from),
		Body:       body,
		ReceivedAt: receivedAt,
		CreatedAt:  time.Now(),
	}
	s.state.Messages = append(s.state.Messages, msg)
	s.state.Mailboxes[idx].ReceiveCount++
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	return msg, s.saveLocked()
}

func (s *FileStore) UpsertMessage(mailboxID, remoteID, source, subject, from, body string, receivedAt time.Time) (Message, bool, error) {
	return s.UpsertMessageContent(mailboxID, remoteID, source, subject, from, body, "", receivedAt)
}

func (s *FileStore) UpsertMessageContent(mailboxID, remoteID, source, subject, from, body, htmlBody string, receivedAt time.Time) (Message, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(mailboxID)
	if idx < 0 {
		return Message{}, false, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	remoteID = strings.TrimSpace(remoteID)
	if remoteID != "" {
		// IMAP overlap scans usually revisit recently stored UIDs. Searching from
		// newest to oldest avoids walking the full historical message collection.
		for i := len(s.state.Messages) - 1; i >= 0; i-- {
			msg := s.state.Messages[i]
			if msg.MailboxID == mailboxID && msg.RemoteID == remoteID {
				originalMessage := s.state.Messages[i]
				originalMailbox := s.state.Mailboxes[idx]
				s.state.Messages[i].OwnerID = s.state.Mailboxes[idx].OwnerID
				s.state.Messages[i].Source = strings.TrimSpace(source)
				s.state.Messages[i].Subject = strings.TrimSpace(subject)
				s.state.Messages[i].From = strings.TrimSpace(from)
				s.state.Messages[i].Body = body
				s.state.Messages[i].HTMLBody = htmlBody
				if !receivedAt.IsZero() {
					s.state.Messages[i].ReceivedAt = receivedAt
				}
				s.state.Messages[i].CreatedAt = firstNonZeroTime(s.state.Messages[i].CreatedAt, time.Now())
				s.state.Mailboxes[idx].UpdatedAt = time.Now()
				if err := s.saveMailboxMessageLocked(s.state.Mailboxes[idx], s.state.Messages[i]); err != nil {
					s.state.Messages[i] = originalMessage
					s.state.Mailboxes[idx] = originalMailbox
					return Message{}, false, err
				}
				return s.state.Messages[i], false, nil
			}
		}
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	originalNextID := s.state.NextID
	originalMailbox := s.state.Mailboxes[idx]
	msg := Message{
		ID:         s.nextIDLocked("msg"),
		OwnerID:    s.state.Mailboxes[idx].OwnerID,
		MailboxID:  mailboxID,
		RemoteID:   remoteID,
		Source:     strings.TrimSpace(source),
		Subject:    strings.TrimSpace(subject),
		From:       strings.TrimSpace(from),
		Body:       body,
		HTMLBody:   htmlBody,
		ReceivedAt: receivedAt,
		CreatedAt:  time.Now(),
	}
	s.state.Messages = append(s.state.Messages, msg)
	s.state.Mailboxes[idx].ReceiveCount++
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	if err := s.saveMailboxMessageLocked(s.state.Mailboxes[idx], msg); err != nil {
		s.state.Messages = s.state.Messages[:len(s.state.Messages)-1]
		s.state.Mailboxes[idx] = originalMailbox
		s.state.NextID = originalNextID
		return Message{}, false, err
	}
	return msg, true, nil
}

func (s *FileStore) SetMailboxStatus(id string, apiActive *bool, icloudActive *bool, status, note string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if apiActive != nil {
		s.state.Mailboxes[idx].APIActive = *apiActive
	}
	if icloudActive != nil {
		s.state.Mailboxes[idx].ICloudActive = *icloudActive
	}
	if strings.TrimSpace(status) != "" {
		s.state.Mailboxes[idx].Status = strings.TrimSpace(status)
	}
	if strings.TrimSpace(note) != "" {
		s.state.Mailboxes[idx].Note = strings.TrimSpace(note)
	}
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	return s.state.Mailboxes[idx], s.saveLocked()
}

func (s *FileStore) SetMailboxStatuses(ids []string, apiActive *bool, status, note string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			wanted[id] = true
		}
	}
	if len(wanted) == 0 {
		return 0, errCode("mailbox_ids_required", "请先选择需要更新的邮箱", false)
	}
	now := time.Now()
	count := 0
	for i := range s.state.Mailboxes {
		if !wanted[s.state.Mailboxes[i].ID] {
			continue
		}
		if apiActive != nil {
			s.state.Mailboxes[i].APIActive = *apiActive
		}
		if strings.TrimSpace(status) != "" {
			s.state.Mailboxes[i].Status = strings.TrimSpace(status)
		}
		if strings.TrimSpace(note) != "" {
			s.state.Mailboxes[i].Note = strings.TrimSpace(note)
		}
		s.state.Mailboxes[i].UpdatedAt = now
		count++
	}
	if count == 0 {
		return 0, errCode("mailbox_not_found", "没有找到可更新的邮箱", false)
	}
	return count, s.saveLocked()
}

func (s *FileStore) RotateMailboxAPIToken(id string, validDays int) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if validDays < 1 || validDays > 3650 {
		return Mailbox{}, errCode("invalid_api_expiry", "API 有效期必须在 1 到 3650 天之间", false)
	}
	for i := range s.state.Mailboxes {
		if s.state.Mailboxes[i].ID == strings.TrimSpace(id) {
			token, err := randomToken(24)
			if err != nil {
				return Mailbox{}, err
			}
			now := time.Now()
			s.state.Mailboxes[i].APIToken = token
			s.state.Mailboxes[i].APITokenExpiresAt = now.Add(time.Duration(validDays) * 24 * time.Hour)
			s.state.Mailboxes[i].APIActive = true
			s.state.Mailboxes[i].UpdatedAt = now
			return s.state.Mailboxes[i], s.saveLocked()
		}
	}
	return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
}

func (s *FileStore) RotateMailboxAPITokens(ids []string, validDays int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if validDays < 1 || validDays > 3650 {
		return 0, errCode("invalid_api_expiry", "API 有效期必须在 1 到 3650 天之间", false)
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			wanted[id] = true
		}
	}
	if len(wanted) == 0 {
		return 0, errCode("mailbox_ids_required", "请先选择需要重置取码 API 的邮箱", false)
	}
	type tokenUpdate struct {
		index int
		token string
	}
	updates := make([]tokenUpdate, 0, len(wanted))
	for i := range s.state.Mailboxes {
		if !wanted[s.state.Mailboxes[i].ID] {
			continue
		}
		token, err := randomToken(24)
		if err != nil {
			return 0, err
		}
		updates = append(updates, tokenUpdate{index: i, token: token})
	}
	if len(updates) == 0 {
		return 0, errCode("mailbox_not_found", "没有找到可重置的邮箱", false)
	}
	now := time.Now()
	for _, update := range updates {
		s.state.Mailboxes[update.index].APIToken = update.token
		s.state.Mailboxes[update.index].APITokenExpiresAt = now.Add(time.Duration(validDays) * 24 * time.Hour)
		s.state.Mailboxes[update.index].APIActive = true
		s.state.Mailboxes[update.index].UpdatedAt = now
	}
	return len(updates), s.saveLocked()
}

func (s *FileStore) RotateAllMailboxAPITokens(validDays int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if validDays < 1 || validDays > 3650 {
		return 0, errCode("invalid_valid_days", "API 地址有效天数必须为 1 到 3650", false)
	}
	now := time.Now()
	for i := range s.state.Mailboxes {
		token, err := randomToken(24)
		if err != nil {
			return 0, err
		}
		s.state.Mailboxes[i].APIToken = token
		s.state.Mailboxes[i].APITokenExpiresAt = now.Add(time.Duration(validDays) * 24 * time.Hour)
		s.state.Mailboxes[i].UpdatedAt = now
	}
	return len(s.state.Mailboxes), s.saveLocked()
}

func (s *FileStore) SetMailboxSyncCursor(id string, syncedAt time.Time, lastUID string) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	if syncedAt.IsZero() {
		syncedAt = time.Now()
	}
	original := s.state.Mailboxes[idx]
	s.state.Mailboxes[idx].LastSyncAt = syncedAt
	if strings.TrimSpace(lastUID) != "" {
		s.state.Mailboxes[idx].LastSyncUID = strings.TrimSpace(lastUID)
	}
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	updated := s.state.Mailboxes[idx]
	if err := s.saveMailboxLocked(updated); err != nil {
		s.state.Mailboxes[idx] = original
		return Mailbox{}, err
	}
	return updated, nil
}

func (s *FileStore) SetICloudIMAPSyncCursor(ownerID, accountID, stateKey string, syncedAt time.Time, lastUID string) (ICloudSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	stateKey = strings.TrimSpace(stateKey)
	if syncedAt.IsZero() {
		syncedAt = time.Now()
	}
	updateSession := func(session *ICloudSession) bool {
		if session == nil {
			return false
		}
		if ownerID != "" && !constantTimeEqual(ownerID, session.OwnerID) {
			return false
		}
		if accountID != "" && !constantTimeEqual(accountID, session.AccountID) {
			return false
		}
		for i, state := range session.LoginStates {
			if state.Kind != LoginStateICloudIMAP {
				continue
			}
			if accountID == "" && stateKey != "" && imapStateKey(state) != stateKey {
				continue
			}
			session.LoginStates[i].IMAPLastSyncAt = syncedAt
			if strings.TrimSpace(lastUID) != "" {
				session.LoginStates[i].IMAPLastSyncUID = strings.TrimSpace(lastUID)
			}
			return true
		}
		return false
	}
	if ownerID == "" && s.state.ICloudSession != nil && updateSession(s.state.ICloudSession) {
		return cloneICloudSession(*s.state.ICloudSession), s.saveLocked()
	}
	for i := range s.state.ICloudSessions {
		original := cloneICloudSession(s.state.ICloudSessions[i])
		if updateSession(&s.state.ICloudSessions[i]) {
			updated := cloneICloudSession(s.state.ICloudSessions[i])
			if err := s.saveICloudSessionRowLocked(updated); err != nil {
				s.state.ICloudSessions[i] = original
				return ICloudSession{}, err
			}
			return updated, nil
		}
	}
	return ICloudSession{}, errCode("imap_session_missing", "未找到取码登录态，无法保存 IMAP 同步游标", true)
}

func (s *FileStore) SetMailboxLastCode(id string, messageID string, servedAt time.Time) (Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, errCode("mailbox_not_found", "邮箱不存在", false)
	}
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return Mailbox{}, errCode("message_id_missing", "验证码邮件 ID 为空", false)
	}
	if servedAt.IsZero() {
		servedAt = time.Now()
	}
	original := s.state.Mailboxes[idx]
	s.state.Mailboxes[idx].LastCodeMessageID = messageID
	s.state.Mailboxes[idx].LastCodeAt = servedAt
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	updated := s.state.Mailboxes[idx]
	if err := s.saveMailboxLocked(updated); err != nil {
		s.state.Mailboxes[idx] = original
		return Mailbox{}, err
	}
	return updated, nil
}

func (s *FileStore) DeleteMailbox(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return errCode("mailbox_not_found", "邮箱不存在", false)
	}
	s.state.Mailboxes = append(s.state.Mailboxes[:idx], s.state.Mailboxes[idx+1:]...)
	filtered := s.state.Messages[:0]
	for _, msg := range s.state.Messages {
		if msg.MailboxID != id {
			filtered = append(filtered, msg)
		}
	}
	s.state.Messages = filtered
	return s.saveLocked()
}

func (s *FileStore) FindMailboxByID(id string) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.mailboxIndexLocked(id)
	if idx < 0 {
		return Mailbox{}, false
	}
	return s.state.Mailboxes[idx], true
}

func (s *FileStore) FindMailboxByEmail(email string) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, mailbox := range s.state.Mailboxes {
		if strings.EqualFold(mailbox.Email, email) {
			return mailbox, true
		}
	}
	return Mailbox{}, false
}

func (s *FileStore) MessagesForMailbox(mailboxID string) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Message
	for _, msg := range s.state.Messages {
		if msg.MailboxID == mailboxID {
			out = append(out, msg)
		}
	}
	return out
}

func (s *FileStore) MarkMailboxesExported(ids []string, exportedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		wanted[strings.TrimSpace(id)] = struct{}{}
	}
	for i := range s.state.Mailboxes {
		if _, ok := wanted[s.state.Mailboxes[i].ID]; ok {
			s.state.Mailboxes[i].ExportedAt = exportedAt
			s.state.Mailboxes[i].UpdatedAt = exportedAt
		}
	}
	return s.saveLocked()
}

func (s *FileStore) RedemptionPoolForOwner(ownerID string) (RedemptionPool, error) {
	return s.RedemptionPoolForOwnerType(ownerID, "primary", 0)
}

func (s *FileStore) RedemptionPoolForOwnerType(ownerID, poolType string, eligibilityDays int) (RedemptionPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ownerID = strings.TrimSpace(ownerID)
	poolType = firstNonEmpty(strings.TrimSpace(poolType), "primary")
	for _, pool := range s.state.RedemptionPools {
		if constantTimeEqual(pool.OwnerID, ownerID) && firstNonEmpty(pool.PoolType, "primary") == poolType {
			return pool, nil
		}
	}
	token, err := randomToken(32)
	if err != nil {
		return RedemptionPool{}, err
	}
	now := time.Now()
	pool := RedemptionPool{ID: s.nextIDLocked("pool"), OwnerID: ownerID, PoolType: poolType, EligibilityDays: eligibilityDays, PublicToken: token, Enabled: true, CreatedAt: now, UpdatedAt: now}
	s.state.RedemptionPools = append(s.state.RedemptionPools, pool)
	return pool, s.saveLocked()
}

func (s *FileStore) RedemptionPoolByToken(token string) (RedemptionPool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pool := range s.state.RedemptionPools {
		if pool.Enabled && constantTimeEqual(pool.PublicToken, token) {
			return pool, true
		}
	}
	return RedemptionPool{}, false
}

func (s *FileStore) MailboxRedemptionLocked(mailboxID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	mailboxID = strings.TrimSpace(mailboxID)
	for _, mailbox := range s.state.Mailboxes {
		if mailbox.ID == mailboxID && mailbox.RedemptionLocked {
			return true
		}
	}
	for _, item := range s.state.RedemptionItems {
		if item.MailboxID == mailboxID {
			return true
		}
	}
	return false
}

func (s *FileStore) AddRedemptionItems(ownerID string, ids []string, healthy map[string]bool) (int, error) {
	return s.addRedemptionItems(ownerID, "primary", ids, healthy)
}

func (s *FileStore) AddSecondhandRedemptionItems(ownerID string, ids []string, healthy map[string]bool) (int, error) {
	return s.addRedemptionItems(ownerID, "secondhand", ids, healthy)
}

func (s *FileStore) addRedemptionItems(ownerID, poolType string, ids []string, healthy map[string]bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pool *RedemptionPool
	for i := range s.state.RedemptionPools {
		if constantTimeEqual(s.state.RedemptionPools[i].OwnerID, ownerID) && firstNonEmpty(s.state.RedemptionPools[i].PoolType, "primary") == poolType {
			pool = &s.state.RedemptionPools[i]
			break
		}
	}
	if pool == nil {
		token, err := randomToken(32)
		if err != nil {
			return 0, err
		}
		now := time.Now()
		s.state.RedemptionPools = append(s.state.RedemptionPools, RedemptionPool{ID: s.nextIDLocked("pool"), OwnerID: ownerID, PoolType: poolType, EligibilityDays: map[string]int{"secondhand": 7}[poolType], PublicToken: token, Enabled: true, CreatedAt: now, UpdatedAt: now})
		pool = &s.state.RedemptionPools[len(s.state.RedemptionPools)-1]
	}
	existing := map[string]bool{}
	for _, item := range s.state.RedemptionItems {
		if item.RedeemedAt.IsZero() {
			existing[item.MailboxID] = true
		}
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[strings.TrimSpace(id)] = true
	}
	count := 0
	now := time.Now()
	for _, mailbox := range s.state.Mailboxes {
		eligibleExport := mailbox.ExportedAt.IsZero()
		if poolType == "secondhand" {
			eligibleExport = !mailbox.ExportedAt.IsZero() && mailbox.ExportedAt.Before(now.Add(-7*24*time.Hour))
		}
		if !wanted[mailbox.ID] || existing[mailbox.ID] || !constantTimeEqual(mailbox.OwnerID, ownerID) || !eligibleExport || !mailbox.APIActive || !mailbox.ICloudActive || mailbox.Status != StatusAvailable || !healthy[mailbox.ID] {
			continue
		}
		s.state.RedemptionItems = append(s.state.RedemptionItems, RedemptionItem{PoolID: pool.ID, OwnerID: ownerID, MailboxID: mailbox.ID, AddedAt: now})
		for i := range s.state.Mailboxes {
			if s.state.Mailboxes[i].ID == mailbox.ID {
				s.state.Mailboxes[i].RedemptionLocked = true
				s.state.Mailboxes[i].UpdatedAt = now
				break
			}
		}
		count++
	}
	if count == 0 {
		return 0, errCode("no_eligible_mailboxes", "没有可加入的邮箱；仅支持未导出、状态可用且可正常接码的邮箱", false)
	}
	pool.UpdatedAt = now
	return count, s.saveLocked()
}

func (s *FileStore) RemoveRedemptionItems(ownerID string, ids []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[strings.TrimSpace(id)] = true
	}
	next := s.state.RedemptionItems[:0]
	count := 0
	now := time.Now()
	for _, item := range s.state.RedemptionItems {
		if constantTimeEqual(item.OwnerID, ownerID) && item.RedeemedAt.IsZero() && wanted[item.MailboxID] {
			for i := range s.state.Mailboxes {
				if s.state.Mailboxes[i].ID == item.MailboxID {
					s.state.Mailboxes[i].RedemptionLocked = true
					s.state.Mailboxes[i].UpdatedAt = now
					break
				}
			}
			count++
			continue
		}
		next = append(next, item)
	}
	s.state.RedemptionItems = next
	if count == 0 {
		return 0, nil
	}
	return count, s.saveLocked()
}

func (s *FileStore) CreateRedemptionCode(ownerID string, quantity int) (RedemptionCode, error) {
	rows, err := s.CreateRedemptionCodes(ownerID, quantity, 1, "", 0)
	if err != nil {
		return RedemptionCode{}, err
	}
	return rows[0], nil
}

func (s *FileStore) CreateRedemptionCodes(ownerID string, quantity, count int, batchName string, validDays int) ([]RedemptionCode, error) {
	return s.CreateRedemptionCodesForPool(ownerID, "primary", quantity, count, batchName, validDays)
}

func (s *FileStore) CreateRedemptionCodesForPool(ownerID, poolType string, quantity, count int, batchName string, validDays int) ([]RedemptionCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if quantity < 1 || quantity > 500 {
		return nil, errCode("invalid_quantity", "单个兑换码数量必须在 1 到 500 之间", false)
	}
	if count < 1 || count > 1000 {
		return nil, errCode("invalid_code_count", "每批兑换码数量必须在 1 到 1000 之间", false)
	}
	if validDays < 0 || validDays > 3650 {
		return nil, errCode("invalid_valid_days", "有效天数必须为 0 到 3650，0 表示永久有效", false)
	}
	poolID := ""
	poolType = firstNonEmpty(strings.TrimSpace(poolType), "primary")
	for _, p := range s.state.RedemptionPools {
		if constantTimeEqual(p.OwnerID, ownerID) && firstNonEmpty(p.PoolType, "primary") == poolType {
			poolID = p.ID
			break
		}
	}
	if poolID == "" {
		return nil, errCode("redemption_pool_missing", "请先创建兑换池", false)
	}
	now := time.Now()
	result := make([]RedemptionCode, 0, count)
	for i := 0; i < count; i++ {
		raw, err := randomToken(12)
		if err != nil {
			return nil, err
		}
		code := "MAIL-" + strings.ToUpper(raw)
		row := RedemptionCode{ID: s.nextIDLocked("redeem"), PoolID: poolID, OwnerID: ownerID, Code: code, CodeHash: sessionTokenHash(code), Quantity: quantity, BatchName: strings.TrimSpace(batchName), CreatedAt: now}
		if validDays > 0 {
			row.ExpiresAt = now.Add(time.Duration(validDays) * 24 * time.Hour)
		}
		s.state.RedemptionCodes = append(s.state.RedemptionCodes, row)
		result = append(result, row)
	}
	return result, s.saveLocked()
}

func (s *FileStore) RedemptionDataForOwner(ownerID string) (RedemptionPool, []RedemptionCode, []RedemptionItem) {
	return s.RedemptionDataForOwnerType(ownerID, "primary")
}

func (s *FileStore) RedemptionDataForOwnerType(ownerID, poolType string) (RedemptionPool, []RedemptionCode, []RedemptionItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	poolType = firstNonEmpty(strings.TrimSpace(poolType), "primary")
	var pool RedemptionPool
	var codes []RedemptionCode
	var items []RedemptionItem
	for _, p := range s.state.RedemptionPools {
		if constantTimeEqual(p.OwnerID, ownerID) && firstNonEmpty(p.PoolType, "primary") == poolType {
			pool = p
		}
	}
	for _, c := range s.state.RedemptionCodes {
		if constantTimeEqual(c.OwnerID, ownerID) && c.PoolID == pool.ID {
			c.RedeemedMailboxIDs = append([]string(nil), c.RedeemedMailboxIDs...)
			codes = append(codes, c)
		}
	}
	for _, i := range s.state.RedemptionItems {
		if constantTimeEqual(i.OwnerID, ownerID) && i.PoolID == pool.ID {
			items = append(items, i)
		}
	}
	return pool, codes, items
}

func (s *FileStore) RedeemMailboxes(poolToken, code string, healthy map[string]bool) (RedemptionCode, []Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pool *RedemptionPool
	for i := range s.state.RedemptionPools {
		if s.state.RedemptionPools[i].Enabled && constantTimeEqual(s.state.RedemptionPools[i].PublicToken, poolToken) {
			pool = &s.state.RedemptionPools[i]
			break
		}
	}
	if pool == nil {
		return RedemptionCode{}, nil, errCode("pool_not_found", "兑换池不存在或已停用", false)
	}
	codeHash := sessionTokenHash(strings.TrimSpace(code))
	var row *RedemptionCode
	for i := range s.state.RedemptionCodes {
		if s.state.RedemptionCodes[i].PoolID == pool.ID && constantTimeEqual(s.state.RedemptionCodes[i].CodeHash, codeHash) {
			row = &s.state.RedemptionCodes[i]
			break
		}
	}
	if row == nil {
		return RedemptionCode{}, nil, errCode("invalid_redemption_code", "兑换码不正确", false)
	}
	if row.Invalidated {
		return RedemptionCode{}, nil, errCode("redemption_code_invalidated", "该兑换码已经失效", false)
	}
	if !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(time.Now()) {
		return RedemptionCode{}, nil, errCode("redemption_code_expired", "该兑换码已经过期", false)
	}
	if row.Used {
		return RedemptionCode{}, nil, errCode("redemption_code_used", "该兑换码已经使用过", false)
	}
	mailboxByID := map[string]int{}
	for i := range s.state.Mailboxes {
		mailboxByID[s.state.Mailboxes[i].ID] = i
	}
	candidates := []int{}
	for i, item := range s.state.RedemptionItems {
		if item.PoolID != pool.ID || !item.RedeemedAt.IsZero() || !healthy[item.MailboxID] {
			continue
		}
		mi, ok := mailboxByID[item.MailboxID]
		if !ok {
			continue
		}
		m := s.state.Mailboxes[mi]
		if (firstNonEmpty(pool.PoolType, "primary") != "secondhand" && !m.ExportedAt.IsZero()) || !m.APIActive || !m.ICloudActive || m.Status != StatusAvailable {
			continue
		}
		candidates = append(candidates, i)
		if len(candidates) == row.Quantity {
			break
		}
	}
	if len(candidates) < row.Quantity {
		return RedemptionCode{}, nil, errCode("insufficient_pool_stock", fmt.Sprintf("兑换池当前只有 %d 个可兑换邮箱，少于兑换码要求的 %d 个", len(candidates), row.Quantity), false)
	}
	now := time.Now()
	result := make([]Mailbox, 0, len(candidates))
	ids := make([]string, 0, len(candidates))
	for _, ii := range candidates {
		item := &s.state.RedemptionItems[ii]
		mi := mailboxByID[item.MailboxID]
		s.state.Mailboxes[mi].ExportedAt = now
		s.state.Mailboxes[mi].UpdatedAt = now
		item.RedeemedAt = now
		item.CodeID = row.ID
		result = append(result, s.state.Mailboxes[mi])
		ids = append(ids, item.MailboxID)
	}
	row.Used = true
	row.UsedAt = now
	row.RedeemedMailboxIDs = ids
	pool.RedeemedCount += len(ids)
	pool.UpdatedAt = now
	if err := s.saveLocked(); err != nil {
		return RedemptionCode{}, nil, err
	}
	return *row, result, nil
}

func (s *FileStore) RedeemMultipleCodes(poolToken string, codes []string, healthy map[string]bool) ([]RedemptionCode, []Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pool *RedemptionPool
	for i := range s.state.RedemptionPools {
		if s.state.RedemptionPools[i].Enabled && constantTimeEqual(s.state.RedemptionPools[i].PublicToken, poolToken) {
			pool = &s.state.RedemptionPools[i]
			break
		}
	}
	if pool == nil {
		return nil, nil, errCode("pool_not_found", "兑换池不存在或已停用", false)
	}
	if len(codes) < 1 || len(codes) > 100 {
		return nil, nil, errCode("invalid_redemption_code_count", "每次可同时兑换 1 到 100 个兑换码", false)
	}

	seen := map[string]bool{}
	selected := make([]int, 0, len(codes))
	required := 0
	now := time.Now()
	for _, raw := range codes {
		hash := sessionTokenHash(strings.TrimSpace(raw))
		if seen[hash] {
			return nil, nil, errCode("duplicate_redemption_code", "提交内容中存在重复兑换码", false)
		}
		seen[hash] = true
		idx := -1
		for i := range s.state.RedemptionCodes {
			if s.state.RedemptionCodes[i].PoolID == pool.ID && constantTimeEqual(s.state.RedemptionCodes[i].CodeHash, hash) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, nil, errCode("invalid_redemption_code", "存在不正确的兑换码，整批未兑换", false)
		}
		row := s.state.RedemptionCodes[idx]
		if row.Invalidated {
			return nil, nil, errCode("redemption_code_invalidated", "存在已经失效的兑换码，整批未兑换", false)
		}
		if row.Used {
			return nil, nil, errCode("redemption_code_used", "存在已经使用过的兑换码，整批未兑换", false)
		}
		if !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(now) {
			return nil, nil, errCode("redemption_code_expired", "存在已经过期的兑换码，整批未兑换", false)
		}
		selected = append(selected, idx)
		required += row.Quantity
	}

	mailboxByID := map[string]int{}
	for i := range s.state.Mailboxes {
		mailboxByID[s.state.Mailboxes[i].ID] = i
	}
	candidates := make([]int, 0, required)
	for i, item := range s.state.RedemptionItems {
		if item.PoolID != pool.ID || !item.RedeemedAt.IsZero() || !healthy[item.MailboxID] {
			continue
		}
		mi, ok := mailboxByID[item.MailboxID]
		if !ok {
			continue
		}
		m := s.state.Mailboxes[mi]
		if (firstNonEmpty(pool.PoolType, "primary") != "secondhand" && !m.ExportedAt.IsZero()) || !m.APIActive || !m.ICloudActive || m.Status != StatusAvailable {
			continue
		}
		candidates = append(candidates, i)
		if len(candidates) == required {
			break
		}
	}
	if len(candidates) < required {
		return nil, nil, errCode("insufficient_pool_stock", fmt.Sprintf("兑换池当前只有 %d 个可兑换邮箱，本批兑换码共需要 %d 个", len(candidates), required), false)
	}

	resultCodes := make([]RedemptionCode, 0, len(selected))
	resultBoxes := make([]Mailbox, 0, required)
	cursor := 0
	for _, ci := range selected {
		row := &s.state.RedemptionCodes[ci]
		ids := make([]string, 0, row.Quantity)
		for j := 0; j < row.Quantity; j++ {
			item := &s.state.RedemptionItems[candidates[cursor]]
			cursor++
			mi := mailboxByID[item.MailboxID]
			s.state.Mailboxes[mi].ExportedAt = now
			s.state.Mailboxes[mi].UpdatedAt = now
			item.RedeemedAt = now
			item.CodeID = row.ID
			ids = append(ids, item.MailboxID)
			resultBoxes = append(resultBoxes, s.state.Mailboxes[mi])
		}
		row.Used = true
		row.UsedAt = now
		row.RedeemedMailboxIDs = ids
		resultCodes = append(resultCodes, *row)
	}
	pool.RedeemedCount += required
	pool.UpdatedAt = now
	if err := s.saveLocked(); err != nil {
		return nil, nil, err
	}
	return resultCodes, resultBoxes, nil
}

func (s *FileStore) CreateRedemptionOrder(poolToken, password string, codes []RedemptionCode, boxes []Mailbox, exportLines ...[]string) (RedemptionOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	password = strings.TrimSpace(password)
	if len([]rune(password)) < 4 || len([]rune(password)) > 64 {
		return RedemptionOrder{}, errCode("invalid_lookup_password", "查单密码需为 4 到 64 个字符", false)
	}
	var pool *RedemptionPool
	for i := range s.state.RedemptionPools {
		if s.state.RedemptionPools[i].Enabled && constantTimeEqual(s.state.RedemptionPools[i].PublicToken, poolToken) {
			pool = &s.state.RedemptionPools[i]
			break
		}
	}
	if pool == nil {
		return RedemptionOrder{}, errCode("pool_not_found", "兑换池不存在或已停用", false)
	}
	row := RedemptionOrder{ID: s.nextIDLocked("order"), PoolID: pool.ID, OwnerID: pool.OwnerID, PasswordHash: sessionTokenHash(password), RedeemedAt: time.Now()}
	for _, code := range codes {
		row.CodeIDs = append(row.CodeIDs, code.ID)
	}
	for _, mailbox := range boxes {
		row.MailboxIDs = append(row.MailboxIDs, mailbox.ID)
	}
	if len(exportLines) > 0 {
		row.ExportLines = append([]string(nil), exportLines[0]...)
	}
	s.state.RedemptionOrders = append(s.state.RedemptionOrders, row)
	return row, s.saveLocked()
}

func (s *FileStore) RedemptionOrdersByPassword(poolToken, password string) ([]RedemptionOrder, []Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pool *RedemptionPool
	for i := range s.state.RedemptionPools {
		if s.state.RedemptionPools[i].Enabled && constantTimeEqual(s.state.RedemptionPools[i].PublicToken, poolToken) {
			pool = &s.state.RedemptionPools[i]
			break
		}
	}
	if pool == nil {
		return nil, nil, errCode("pool_not_found", "兑换池不存在或已停用", false)
	}
	hash := sessionTokenHash(strings.TrimSpace(password))
	orders := make([]RedemptionOrder, 0)
	boxes := make([]Mailbox, 0)
	mailboxByID := make(map[string]Mailbox, len(s.state.Mailboxes))
	for _, mailbox := range s.state.Mailboxes {
		mailboxByID[mailbox.ID] = mailbox
	}
	for i := len(s.state.RedemptionOrders) - 1; i >= 0; i-- {
		row := s.state.RedemptionOrders[i]
		if row.PoolID != pool.ID || !constantTimeEqual(row.PasswordHash, hash) {
			continue
		}
		orders = append(orders, row)
		for _, id := range row.MailboxIDs {
			if mailbox, ok := mailboxByID[id]; ok {
				boxes = append(boxes, mailbox)
			}
		}
	}
	if len(orders) == 0 {
		return nil, nil, errCode("order_not_found", "未找到与该查单密码匹配的兑换记录", false)
	}
	return orders, boxes, nil
}

func (s *FileStore) RotateRedemptionCode(ownerID, code string) (RedemptionCode, []Mailbox, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := sessionTokenHash(strings.TrimSpace(code))
	var row *RedemptionCode
	for i := range s.state.RedemptionCodes {
		if constantTimeEqual(s.state.RedemptionCodes[i].OwnerID, ownerID) && constantTimeEqual(s.state.RedemptionCodes[i].CodeHash, hash) {
			row = &s.state.RedemptionCodes[i]
			break
		}
	}
	if row == nil {
		return RedemptionCode{}, nil, errCode("invalid_redemption_code", "兑换码不存在", false)
	}
	if !row.Used {
		return RedemptionCode{}, nil, errCode("redemption_code_unused", "兑换码尚未使用，不能重置取码地址", false)
	}
	if row.Invalidated {
		return RedemptionCode{}, nil, errCode("redemption_code_invalidated", "该兑换码已经失效", false)
	}
	now := time.Now()
	result := []Mailbox{}
	secondhand := false
	for i := range s.state.RedemptionPools {
		if s.state.RedemptionPools[i].ID == row.PoolID {
			secondhand = firstNonEmpty(s.state.RedemptionPools[i].PoolType, "primary") == "secondhand"
			break
		}
	}
	for _, id := range row.RedeemedMailboxIDs {
		for i := range s.state.Mailboxes {
			if s.state.Mailboxes[i].ID == id {
				token, err := randomToken(24)
				if err != nil {
					return RedemptionCode{}, nil, err
				}
				s.state.Mailboxes[i].APIToken = token
				if secondhand {
					// A secondhand mailbox starts a fresh cooldown after its API is
					// rotated. It must not immediately return to available stock.
					s.state.Mailboxes[i].ExportedAt = now
				} else {
					s.state.Mailboxes[i].ExportedAt = time.Time{}
				}
				s.state.Mailboxes[i].UpdatedAt = now
				result = append(result, s.state.Mailboxes[i])
				break
			}
		}
	}
	for i := range s.state.RedemptionItems {
		if s.state.RedemptionItems[i].CodeID == row.ID {
			if !secondhand {
				s.state.RedemptionItems[i].RedeemedAt = time.Time{}
				s.state.RedemptionItems[i].CodeID = ""
			}
		}
	}
	row.RotatedAt = now
	row.RotationCount++
	row.Invalidated = true
	row.InvalidatedAt = now
	for i := range s.state.RedemptionPools {
		if s.state.RedemptionPools[i].ID == row.PoolID {
			if !secondhand {
				s.state.RedemptionPools[i].RedeemedCount = max(0, s.state.RedemptionPools[i].RedeemedCount-len(result))
			}
			s.state.RedemptionPools[i].UpdatedAt = now
			break
		}
	}
	if err := s.saveLocked(); err != nil {
		return RedemptionCode{}, nil, err
	}
	return *row, result, nil
}

func (s *FileStore) DeleteMessagesForMailbox(mailboxID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mailboxID = strings.TrimSpace(mailboxID)
	next := s.state.Messages[:0]
	deleted := 0
	for _, msg := range s.state.Messages {
		if msg.MailboxID == mailboxID {
			deleted++
			continue
		}
		next = append(next, msg)
	}
	s.state.Messages = next
	for i := range s.state.Mailboxes {
		if s.state.Mailboxes[i].ID == mailboxID {
			s.state.Mailboxes[i].LastCodeMessageID = ""
			s.state.Mailboxes[i].LastCodeAt = time.Time{}
			s.state.Mailboxes[i].UpdatedAt = time.Now()
			break
		}
	}
	return deleted, s.saveLocked()
}

func (s *FileStore) PruneMessages(retentionDays, maxPerMailbox int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if retentionDays < 1 {
		retentionDays = 60
	}
	if maxPerMailbox < 1 {
		maxPerMailbox = 200
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	byMailbox := map[string][]Message{}
	for _, m := range s.state.Messages {
		byMailbox[m.MailboxID] = append(byMailbox[m.MailboxID], m)
	}
	keep := map[string]bool{}
	for _, rows := range byMailbox {
		sort.Slice(rows, func(i, j int) bool { return rows[i].ReceivedAt.After(rows[j].ReceivedAt) })
		for i, m := range rows {
			if i < maxPerMailbox && !m.ReceivedAt.Before(cutoff) {
				keep[m.ID] = true
			}
		}
	}
	next := s.state.Messages[:0]
	removed := 0
	for _, m := range s.state.Messages {
		if keep[m.ID] {
			next = append(next, m)
		} else {
			removed++
		}
	}
	s.state.Messages = next
	if removed == 0 {
		return 0, nil
	}
	return removed, s.saveLocked()
}

func (s *FileStore) VacuumDatabase() error {
	db, err := s.sqliteConnection()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`VACUUM`)
	return err
}

func (s *FileStore) nextIDLocked(prefix string) string {
	id := fmt.Sprintf("%s_%06d", prefix, s.state.NextID)
	s.state.NextID++
	return id
}

func (s *FileStore) ensureICloudAccountLocked(ownerID string, session ICloudSession) string {
	ownerID = strings.TrimSpace(ownerID)
	for _, existing := range s.state.ICloudSessions {
		if constantTimeEqual(ownerID, existing.OwnerID) && sameICloudSessionIdentity(existing, session) && strings.TrimSpace(existing.AccountID) != "" {
			s.touchICloudAccountLocked(ownerID, existing.AccountID, session)
			return existing.AccountID
		}
	}

	appleID := strings.TrimSpace(session.AppleID)
	loginIdentifier := normalizeAppleLoginIdentifier(firstNonEmpty(session.LoginIdentifier, session.AppleID))
	if loginIdentifier != "" {
		for i, account := range s.state.Accounts {
			if constantTimeEqual(ownerID, account.OwnerID) && normalizeAppleLoginIdentifier(firstNonEmpty(account.LoginIdentifier, account.AppleID)) == loginIdentifier {
				s.updateICloudAccountFromSessionLocked(i, session)
				return account.ID
			}
		}
	}
	if appleID != "" {
		for i, account := range s.state.Accounts {
			if constantTimeEqual(ownerID, account.OwnerID) && strings.EqualFold(strings.TrimSpace(account.AppleID), appleID) {
				s.updateICloudAccountFromSessionLocked(i, session)
				return account.ID
			}
		}
	}

	now := time.Now()
	label := appleID
	if label == "" && strings.TrimSpace(session.DSID) != "" {
		label = "iCloud " + maskSecret(session.DSID, 4)
	}
	if label == "" {
		label = "iCloud " + now.Format("0102-150405")
	}
	account := Account{
		ID:              s.nextIDLocked("acc"),
		OwnerID:         ownerID,
		Label:           label,
		AppleID:         appleID,
		LoginIdentifier: loginIdentifier,
		Status:          StatusActive,
		ICloudStatus:    iCloudStatusFromSession(session),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	s.state.Accounts = append(s.state.Accounts, account)
	return account.ID
}

func (s *FileStore) touchICloudAccountLocked(ownerID, accountID string, session ICloudSession) {
	ownerID = strings.TrimSpace(ownerID)
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return
	}
	for i, account := range s.state.Accounts {
		if account.ID == accountID && constantTimeEqual(ownerID, account.OwnerID) {
			s.updateICloudAccountFromSessionLocked(i, session)
			return
		}
	}
}

func (s *FileStore) updateICloudAccountFromSessionLocked(index int, session ICloudSession) {
	if index < 0 || index >= len(s.state.Accounts) {
		return
	}
	account := &s.state.Accounts[index]
	if appleID := strings.TrimSpace(session.AppleID); appleID != "" {
		account.AppleID = appleID
		if strings.TrimSpace(account.Label) == "" || strings.HasPrefix(strings.TrimSpace(account.Label), "iCloud ") {
			account.Label = appleID
		}
	}
	if loginIdentifier := normalizeAppleLoginIdentifier(firstNonEmpty(session.LoginIdentifier, session.AppleID)); loginIdentifier != "" {
		account.LoginIdentifier = loginIdentifier
	}
	account.Status = StatusActive
	account.ICloudStatus = iCloudStatusFromSession(session)
	account.UpdatedAt = time.Now()
}

func sameICloudSessionIdentity(a, b ICloudSession) bool {
	leftAccountID := strings.TrimSpace(a.AccountID)
	rightAccountID := strings.TrimSpace(b.AccountID)
	if leftAccountID != "" && rightAccountID != "" {
		return constantTimeEqual(leftAccountID, rightAccountID)
	}
	if strings.TrimSpace(a.DSID) != "" && constantTimeEqual(a.DSID, b.DSID) {
		return true
	}
	leftLogin := normalizeAppleLoginIdentifier(firstNonEmpty(a.LoginIdentifier, a.AppleID))
	rightLogin := normalizeAppleLoginIdentifier(firstNonEmpty(b.LoginIdentifier, b.AppleID))
	if leftLogin != "" && leftLogin == rightLogin {
		return true
	}
	if strings.TrimSpace(a.AppleID) != "" && strings.EqualFold(strings.TrimSpace(a.AppleID), strings.TrimSpace(b.AppleID)) {
		return true
	}
	return false
}

func normalizeAppleLoginIdentifier(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || strings.Contains(value, "@") {
		return value
	}
	var b strings.Builder
	for i, r := range value {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r == ' ', r == '-', r == '(', r == ')':
			continue
		default:
			return value
		}
	}
	return b.String()
}

func (s *FileStore) pruneDuplicateIMAPOnlySessionsLocked(ownerID string, target ICloudSession, targetIndex int) {
	ownerID = strings.TrimSpace(ownerID)
	targetIMAPEmail := sessionIMAPEmail(target)
	if targetIMAPEmail == "" {
		return
	}
	targetLocal := emailLocalPart(targetIMAPEmail)
	removedAccountIDs := map[string]struct{}{}
	next := s.state.ICloudSessions[:0]
	for i, session := range s.state.ICloudSessions {
		if i == targetIndex || !constantTimeEqual(ownerID, session.OwnerID) {
			next = append(next, session)
			continue
		}
		if hasCreateLoginState(session) {
			next = append(next, session)
			continue
		}
		imapEmail := sessionIMAPEmail(session)
		sameIMAPEmail := targetIMAPEmail != "" && strings.EqualFold(imapEmail, targetIMAPEmail)
		sameLocalPart := targetLocal != "" && strings.EqualFold(emailLocalPart(imapEmail), targetLocal)
		if sameIMAPEmail || sameLocalPart {
			if accountID := strings.TrimSpace(session.AccountID); accountID != "" {
				removedAccountIDs[accountID] = struct{}{}
			}
			continue
		}
		next = append(next, session)
	}
	s.state.ICloudSessions = next
	if len(removedAccountIDs) > 0 {
		s.removeAccountIDsFromCreateSettingsLocked(ownerID, removedAccountIDs)
		s.pruneRemovedIMAPOnlyAccountsLocked(ownerID, removedAccountIDs)
	}
}

func (s *FileStore) removeAccountIDsFromCreateSettingsLocked(ownerID string, accountIDs map[string]struct{}) {
	for i, settings := range s.state.CreateSettings {
		if !constantTimeEqual(ownerID, settings.OwnerID) {
			continue
		}
		next := settings.AccountIDs[:0]
		for _, accountID := range settings.AccountIDs {
			if _, remove := accountIDs[strings.TrimSpace(accountID)]; remove {
				continue
			}
			next = append(next, accountID)
		}
		s.state.CreateSettings[i].AccountIDs = normalizeAccountIDSelection("", next)
		s.state.CreateSettings[i].UpdatedAt = time.Now()
	}
}

func (s *FileStore) pruneRemovedIMAPOnlyAccountsLocked(ownerID string, accountIDs map[string]struct{}) {
	referenced := map[string]struct{}{}
	for _, session := range s.state.ICloudSessions {
		if constantTimeEqual(ownerID, session.OwnerID) {
			if accountID := strings.TrimSpace(session.AccountID); accountID != "" {
				referenced[accountID] = struct{}{}
			}
		}
	}
	for _, mailbox := range s.state.Mailboxes {
		if constantTimeEqual(ownerID, mailbox.OwnerID) {
			if accountID := strings.TrimSpace(mailbox.AccountID); accountID != "" {
				referenced[accountID] = struct{}{}
			}
		}
	}
	next := s.state.Accounts[:0]
	for _, account := range s.state.Accounts {
		accountID := strings.TrimSpace(account.ID)
		if constantTimeEqual(ownerID, account.OwnerID) {
			if _, wasRemovedSessionAccount := accountIDs[accountID]; wasRemovedSessionAccount {
				if _, stillReferenced := referenced[accountID]; !stillReferenced {
					continue
				}
			}
		}
		next = append(next, account)
	}
	s.state.Accounts = next
}

func hasCreateLoginState(session ICloudSession) bool {
	if len(session.Cookies) > 0 {
		return true
	}
	for _, state := range session.LoginStates {
		if state.Kind == LoginStateICloudWeb && len(state.Cookies) > 0 {
			return true
		}
		if state.Kind == LoginStateAppleAccount && strings.TrimSpace(state.Scnt) != "" {
			return true
		}
	}
	return false
}

func sessionIMAPEmail(session ICloudSession) string {
	for _, state := range session.LoginStates {
		if state.Kind != LoginStateICloudIMAP {
			continue
		}
		email := normalizeICloudIMAPEmail(firstNonEmpty(state.IMAPEmail, state.IMAPUsername, session.AppleID))
		if email != "" && strings.TrimSpace(state.IMAPAppPassword) != "" {
			return email
		}
	}
	return ""
}

func iCloudStatusFromSession(session ICloudSession) string {
	if len(session.Cookies) == 0 {
		return ICloudStatusNeedLogin
	}
	if !session.IsICloudPlus {
		return ICloudStatusNoICloudPlus
	}
	if !session.CanCreateHME {
		return ICloudStatusFailed
	}
	return ICloudStatusActive
}

func (s *FileStore) mailboxIndexLocked(id string) int {
	for i, mailbox := range s.state.Mailboxes {
		if mailbox.ID == id {
			return i
		}
	}
	return -1
}

func (s *FileStore) userByIDLocked(id string) (User, bool) {
	id = strings.TrimSpace(id)
	for _, user := range s.state.Users {
		if user.ID == id {
			return user, true
		}
	}
	return User{}, false
}

func (s *FileStore) saveLocked() error {
	s.normalizeICloudSessionsLocked()
	return s.saveSQLiteLocked()
}

// normalizeICloudSessionsLocked repairs legacy duplicate session rows before
// persisting normalized SQLite tables. Explicit account IDs are authoritative:
// login identifiers and DSIDs must never merge two different account records.
func (s *FileStore) normalizeICloudSessionsLocked() {
	for i := range s.state.ICloudSessions {
		session := &s.state.ICloudSessions[i]
		ownerID := strings.TrimSpace(session.OwnerID)
		if ownerID != "" && strings.TrimSpace(session.AccountID) == "" {
			session.AccountID = s.ensureICloudAccountLocked(ownerID, *session)
		}
	}

	indexes := make(map[string]int, len(s.state.ICloudSessions))
	next := make([]ICloudSession, 0, len(s.state.ICloudSessions))
	for _, session := range s.state.ICloudSessions {
		ownerID := strings.TrimSpace(session.OwnerID)
		accountID := strings.TrimSpace(session.AccountID)
		if ownerID != "" && accountID != "" {
			key := ownerID + "\x00" + accountID
			if index, ok := indexes[key]; ok {
				next[index] = mergeICloudSession(next[index], session)
				continue
			}
			indexes[key] = len(next)
		}
		next = append(next, session)
	}
	s.state.ICloudSessions = next
}

func (s *FileStore) migrateLegacyMailboxAccountIDsLocked() bool {
	accountsByOwner := make(map[string][]Account)
	for _, account := range s.state.Accounts {
		ownerID := strings.TrimSpace(account.OwnerID)
		accountsByOwner[ownerID] = append(accountsByOwner[ownerID], account)
	}

	changed := false
	now := time.Now()
	for i := range s.state.Mailboxes {
		if strings.TrimSpace(s.state.Mailboxes[i].AccountID) != "" {
			continue
		}
		ownerID := strings.TrimSpace(s.state.Mailboxes[i].OwnerID)
		accounts := accountsByOwner[ownerID]
		if len(accounts) != 1 {
			continue
		}
		s.state.Mailboxes[i].AccountID = accounts[0].ID
		if s.state.Mailboxes[i].UpdatedAt.IsZero() {
			s.state.Mailboxes[i].UpdatedAt = now
		}
		changed = true
	}
	return changed
}

func cloneState(in State) State {
	out := in
	out.Users = append([]User(nil), in.Users...)
	out.WebSessions = append([]WebSession(nil), in.WebSessions...)
	out.Announcements = append([]Announcement(nil), in.Announcements...)
	out.AnnouncementReads = append([]AnnouncementRead(nil), in.AnnouncementReads...)
	out.AutoLoginBindings = append([]AutoLoginBinding(nil), in.AutoLoginBindings...)
	out.AutoLoginLogs = append([]AutoLoginAttempt(nil), in.AutoLoginLogs...)
	for i := range out.AutoLoginLogs {
		out.AutoLoginLogs[i].Steps = append([]AutoLoginStep(nil), in.AutoLoginLogs[i].Steps...)
	}
	out.UserProxyConfigs = append([]UserProxyConfig(nil), in.UserProxyConfigs...)
	for i := range out.UserProxyConfigs {
		out.UserProxyConfigs[i].PoolNodes = append([]ProxyPoolNode(nil), in.UserProxyConfigs[i].PoolNodes...)
	}
	out.RedemptionPools = append([]RedemptionPool(nil), in.RedemptionPools...)
	out.RedemptionCodes = append([]RedemptionCode(nil), in.RedemptionCodes...)
	for i := range out.RedemptionCodes {
		out.RedemptionCodes[i].RedeemedMailboxIDs = append([]string(nil), in.RedemptionCodes[i].RedeemedMailboxIDs...)
	}
	out.RedemptionItems = append([]RedemptionItem(nil), in.RedemptionItems...)
	out.RedemptionOrders = append([]RedemptionOrder(nil), in.RedemptionOrders...)
	for i := range out.RedemptionOrders {
		out.RedemptionOrders[i].CodeIDs = append([]string(nil), in.RedemptionOrders[i].CodeIDs...)
		out.RedemptionOrders[i].MailboxIDs = append([]string(nil), in.RedemptionOrders[i].MailboxIDs...)
	}
	out.Accounts = append([]Account(nil), in.Accounts...)
	for i := range out.Accounts {
		out.Accounts[i].Tags = append([]string(nil), in.Accounts[i].Tags...)
	}
	out.Mailboxes = append([]Mailbox(nil), in.Mailboxes...)
	out.Messages = append([]Message(nil), in.Messages...)
	if in.ICloudSession != nil {
		session := cloneICloudSession(*in.ICloudSession)
		out.ICloudSession = &session
	}
	out.ICloudSessions = cloneICloudSessions(in.ICloudSessions)
	out.CreateSettings = cloneCreateSettings(in.CreateSettings)
	out.Invites = append([]InviteCode(nil), in.Invites...)
	out.InviteUses = append([]InviteUse(nil), in.InviteUses...)
	out.AuditEvents = append([]AuditEvent(nil), in.AuditEvents...)
	out.RecycleBin = append([]RecycleBinItem(nil), in.RecycleBin...)
	for i := range out.RecycleBin {
		out.RecycleBin[i].Data = append(json.RawMessage(nil), in.RecycleBin[i].Data...)
	}
	return out
}

func cloneICloudSession(in ICloudSession) ICloudSession {
	out := in
	out.Cookies = append([]SessionCookie(nil), in.Cookies...)
	out.LoginStates = cloneLoginStates(in.LoginStates)
	return out
}

func mergeICloudSession(existing, incoming ICloudSession) ICloudSession {
	out := incoming
	out.OwnerID = firstNonEmpty(incoming.OwnerID, existing.OwnerID)
	out.AccountID = firstNonEmpty(incoming.AccountID, existing.AccountID)
	if out.SavedAt.IsZero() {
		out.SavedAt = existing.SavedAt
	}
	out.AppleID = preferredAppleAccountName(existing.AppleID, incoming.AppleID)
	out.LoginIdentifier = normalizeAppleLoginIdentifier(firstNonEmpty(incoming.LoginIdentifier, existing.LoginIdentifier, incoming.AppleID, existing.AppleID))
	out.DSID = firstNonEmpty(incoming.DSID, existing.DSID)
	out.ClientID = firstNonEmpty(incoming.ClientID, existing.ClientID)
	out.ClientBuildNumber = firstNonEmpty(incoming.ClientBuildNumber, existing.ClientBuildNumber)
	out.MasteringNumber = firstNonEmpty(incoming.MasteringNumber, existing.MasteringNumber)
	out.PremiumMailBaseURL = firstNonEmpty(incoming.PremiumMailBaseURL, existing.PremiumMailBaseURL)
	out.MailGatewayBaseURL = firstNonEmpty(incoming.MailGatewayBaseURL, existing.MailGatewayBaseURL)
	out.MailBaseURL = firstNonEmpty(incoming.MailBaseURL, existing.MailBaseURL)
	out.Host = firstNonEmpty(incoming.Host, existing.Host)
	out.IsICloudPlus = incoming.IsICloudPlus || existing.IsICloudPlus
	out.CanCreateHME = incoming.CanCreateHME || existing.CanCreateHME
	if len(out.Cookies) == 0 {
		out.Cookies = append([]SessionCookie(nil), existing.Cookies...)
	}
	out.LoginStates = mergeLoginStates(existing.LoginStates, incoming.LoginStates)
	out.Note = firstNonEmpty(incoming.Note, existing.Note)
	if out.LastCheckedAt.IsZero() {
		out.LastCheckedAt = existing.LastCheckedAt
	}
	if !incoming.LastCheckOK {
		out.LastCheckOK = existing.LastCheckOK
	}
	out.LastStatusMessage = firstNonEmpty(incoming.LastStatusMessage, existing.LastStatusMessage)
	out.ProxyNodeTag = firstNonEmpty(incoming.ProxyNodeTag, existing.ProxyNodeTag)
	out.ProxyNodeName = firstNonEmpty(incoming.ProxyNodeName, existing.ProxyNodeName)
	return out
}

func preferredAppleAccountName(existing, incoming string) string {
	existing, incoming = strings.TrimSpace(existing), strings.TrimSpace(incoming)
	if strings.Contains(incoming, "@") || existing == "" {
		return incoming
	}
	if strings.Contains(existing, "@") {
		return existing
	}
	return firstNonEmpty(incoming, existing)
}

func mergeLoginStates(existing, incoming []LoginState) []LoginState {
	out := cloneLoginStates(existing)
	for _, state := range incoming {
		replaced := false
		for i, current := range out {
			if current.Kind == state.Kind {
				next := state
				next.Cookies = append([]SessionCookie(nil), state.Cookies...)
				out[i] = next
				replaced = true
				break
			}
		}
		if !replaced {
			next := state
			next.Cookies = append([]SessionCookie(nil), state.Cookies...)
			out = append(out, next)
		}
	}
	return out
}

func cloneLoginStates(in []LoginState) []LoginState {
	out := make([]LoginState, 0, len(in))
	for _, state := range in {
		next := state
		next.Cookies = append([]SessionCookie(nil), state.Cookies...)
		out = append(out, next)
	}
	return out
}

func cloneICloudSessions(in []ICloudSession) []ICloudSession {
	out := make([]ICloudSession, 0, len(in))
	for _, session := range in {
		out = append(out, cloneICloudSession(session))
	}
	return out
}

func cloneCreateSettings(in []CreateSettings) []CreateSettings {
	out := make([]CreateSettings, 0, len(in))
	for _, settings := range in {
		next := settings
		next.AccountIDs = append([]string(nil), settings.AccountIDs...)
		out = append(out, next)
	}
	return out
}

func filterStateByOwnerLocked(in State, ownerID string) State {
	if ownerID == "" {
		return cloneState(in)
	}
	out := State{NextID: in.NextID}
	for _, user := range in.Users {
		if user.ID == ownerID {
			out.Users = append(out.Users, user)
			break
		}
	}
	for _, account := range in.Accounts {
		if constantTimeEqual(ownerID, account.OwnerID) {
			out.Accounts = append(out.Accounts, account)
		}
	}
	allowedMailboxes := make(map[string]struct{})
	for _, mailbox := range in.Mailboxes {
		if constantTimeEqual(ownerID, mailbox.OwnerID) {
			out.Mailboxes = append(out.Mailboxes, mailbox)
			allowedMailboxes[mailbox.ID] = struct{}{}
		}
	}
	for _, msg := range in.Messages {
		if _, ok := allowedMailboxes[msg.MailboxID]; ok || constantTimeEqual(ownerID, msg.OwnerID) {
			out.Messages = append(out.Messages, msg)
		}
	}
	for _, session := range in.ICloudSessions {
		if constantTimeEqual(ownerID, session.OwnerID) {
			cloned := cloneICloudSession(session)
			if out.ICloudSession == nil {
				first := cloneICloudSession(session)
				out.ICloudSession = &first
			}
			out.ICloudSessions = append(out.ICloudSessions, cloned)
		}
	}
	for _, settings := range in.CreateSettings {
		if constantTimeEqual(ownerID, settings.OwnerID) {
			next := settings
			next.AccountIDs = append([]string(nil), settings.AccountIDs...)
			out.CreateSettings = append(out.CreateSettings, next)
		}
	}
	for _, pool := range in.RedemptionPools {
		if constantTimeEqual(ownerID, pool.OwnerID) {
			out.RedemptionPools = append(out.RedemptionPools, pool)
		}
	}
	for _, code := range in.RedemptionCodes {
		if constantTimeEqual(ownerID, code.OwnerID) {
			code.RedeemedMailboxIDs = append([]string(nil), code.RedeemedMailboxIDs...)
			out.RedemptionCodes = append(out.RedemptionCodes, code)
		}
	}
	for _, item := range in.RedemptionItems {
		if constantTimeEqual(ownerID, item.OwnerID) {
			out.RedemptionItems = append(out.RedemptionItems, item)
		}
	}
	for _, row := range in.RedemptionOrders {
		if constantTimeEqual(ownerID, row.OwnerID) {
			row.CodeIDs = append([]string(nil), row.CodeIDs...)
			row.MailboxIDs = append([]string(nil), row.MailboxIDs...)
			out.RedemptionOrders = append(out.RedemptionOrders, row)
		}
	}
	for _, row := range in.AutoLoginBindings {
		if constantTimeEqual(ownerID, row.OwnerID) {
			out.AutoLoginBindings = append(out.AutoLoginBindings, row)
		}
	}
	for _, row := range in.AutoLoginLogs {
		if constantTimeEqual(ownerID, row.OwnerID) {
			row.Steps = append([]AutoLoginStep(nil), row.Steps...)
			out.AutoLoginLogs = append(out.AutoLoginLogs, row)
		}
	}
	return out
}

func createSettingsForOwnerLocked(state State, ownerID string) CreateSettings {
	ownerID = strings.TrimSpace(ownerID)
	for _, settings := range state.CreateSettings {
		if constantTimeEqual(ownerID, settings.OwnerID) {
			return normalizeCreateSettings(ownerID, settings)
		}
	}
	return defaultCreateSettings(ownerID)
}

func defaultCreateSettings(ownerID string) CreateSettings {
	return CreateSettings{
		OwnerID:                       strings.TrimSpace(ownerID),
		CreateChannel:                 string(mailboxCreateChannelAuto),
		SchedulerCreateChannel:        string(mailboxCreateChannelAuto),
		AppleAccountTwoFactorMethod:   appleTwoFactorMethodTrustedDevice,
		ICloudWebTwoFactorMethod:      appleTwoFactorMethodTrustedDevice,
		SchedulerIntervalMinutes:      int(defaultMailboxSchedulerInterval.Round(time.Minute).Minutes()),
		SchedulerRoundIntervalSeconds: 120,
		TargetMailboxCount:            750,
		MailboxPageSize:               10,
	}
}

func normalizeCreateSettings(ownerID string, settings CreateSettings) CreateSettings {
	defaults := defaultCreateSettings(ownerID)
	out := settings
	out.OwnerID = strings.TrimSpace(ownerID)
	out.Label = strings.TrimSpace(settings.Label)
	out.Note = strings.TrimSpace(settings.Note)
	out.AccountIDs = normalizeAccountIDSelection("", settings.AccountIDs)
	out.CreateChannel = string(normalizeMailboxCreateChannel(mailboxCreateChannel(strings.ToLower(strings.TrimSpace(settings.CreateChannel)))))
	out.SchedulerCreateChannel = string(normalizeMailboxCreateChannel(mailboxCreateChannel(strings.ToLower(strings.TrimSpace(settings.SchedulerCreateChannel)))))
	out.AppleAccountTwoFactorMethod = normalizeAppleTwoFactorMethod(settings.AppleAccountTwoFactorMethod)
	out.ICloudWebTwoFactorMethod = normalizeAppleTwoFactorMethod(settings.ICloudWebTwoFactorMethod)
	if out.SchedulerIntervalMinutes < 1 {
		out.SchedulerIntervalMinutes = defaults.SchedulerIntervalMinutes
	}
	if out.SchedulerIntervalMinutes > 1440 {
		out.SchedulerIntervalMinutes = 1440
	}
	if out.SchedulerRoundIntervalSeconds < 1 {
		out.SchedulerRoundIntervalSeconds = defaults.SchedulerRoundIntervalSeconds
	}
	// Migrate the former five-second default; explicitly customized values are preserved.
	if out.SchedulerRoundIntervalSeconds == 5 {
		out.SchedulerRoundIntervalSeconds = 120
	}
	if out.SchedulerRoundIntervalSeconds > 600 {
		out.SchedulerRoundIntervalSeconds = 600
	}
	if out.TargetMailboxCount < 1 {
		out.TargetMailboxCount = defaults.TargetMailboxCount
	}
	if out.TargetMailboxCount > 750 {
		out.TargetMailboxCount = 750
	}
	if out.MailboxPageSize < 1 {
		out.MailboxPageSize = defaults.MailboxPageSize
	}
	if out.MailboxPageSize > 500 {
		out.MailboxPageSize = 500
	}
	return out
}

type codedError struct {
	code      string
	message   string
	retryable bool
}

func (e codedError) Error() string { return e.message }

func errCode(code, message string, retryable bool) error {
	return codedError{code: code, message: message, retryable: retryable}
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}
