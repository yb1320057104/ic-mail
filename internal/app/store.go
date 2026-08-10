package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type FileStore struct {
	mu    sync.Mutex
	path  string
	state State
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
	s := &FileStore{path: path, state: State{NextID: 1}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	if s.migrateLegacyMailboxAccountIDsLocked() {
		return s.saveLocked()
	}
	return nil
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

func (s *FileStore) CreateUser(username, password string) (User, error) {
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
		IsAdmin:      len(s.state.Users) == 0,
		Status:       StatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.state.Users = append(s.state.Users, user)
	return user, s.saveLocked()
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

func (s *FileStore) UserByID(id string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userByIDLocked(id)
}

func (s *FileStore) DeleteUser(id string) (DeleteUserResult, error) {
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

	return result, s.saveLocked()
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
		ID:           s.nextIDLocked("acc"),
		OwnerID:      strings.TrimSpace(ownerID),
		CreatedBy:    strings.TrimSpace(ownerID),
		AssignedBy:   strings.TrimSpace(ownerID),
		Category:     "未分类",
		Label:        strings.TrimSpace(label),
		AppleID:      strings.TrimSpace(appleID),
		Status:       StatusActive,
		ICloudStatus: ICloudStatusNeedLogin,
		Note:         strings.TrimSpace(note),
		CreatedAt:    now,
		UpdatedAt:    now,
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
		ID:           s.nextIDLocked("mbx"),
		OwnerID:      strings.TrimSpace(ownerID),
		AccountID:    strings.TrimSpace(accountID),
		Label:        strings.TrimSpace(label),
		Email:        email,
		APIToken:     token,
		APIActive:    true,
		ICloudActive: true,
		Status:       StatusAvailable,
		CreatedAt:    now,
		UpdatedAt:    now,
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
		ID:           s.nextIDLocked("mbx"),
		OwnerID:      ownerID,
		AccountID:    accountID,
		Label:        label,
		Email:        email,
		APIToken:     token,
		APIActive:    true,
		ICloudActive: remote.IsActive,
		Status:       status,
		Note:         note,
		CreatedAt:    now,
		UpdatedAt:    now,
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
		for i, msg := range s.state.Messages {
			if msg.MailboxID == mailboxID && msg.RemoteID == remoteID {
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
				return s.state.Messages[i], false, s.saveLocked()
			}
		}
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
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
	return msg, true, s.saveLocked()
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
	s.state.Mailboxes[idx].LastSyncAt = syncedAt
	if strings.TrimSpace(lastUID) != "" {
		s.state.Mailboxes[idx].LastSyncUID = strings.TrimSpace(lastUID)
	}
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	return s.state.Mailboxes[idx], s.saveLocked()
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
		if updateSession(&s.state.ICloudSessions[i]) {
			updated := cloneICloudSession(s.state.ICloudSessions[i])
			return updated, s.saveLocked()
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
	s.state.Mailboxes[idx].LastCodeMessageID = messageID
	s.state.Mailboxes[idx].LastCodeAt = servedAt
	s.state.Mailboxes[idx].UpdatedAt = time.Now()
	return s.state.Mailboxes[idx], s.saveLocked()
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
		ID:           s.nextIDLocked("acc"),
		OwnerID:      ownerID,
		Label:        label,
		AppleID:      appleID,
		Status:       StatusActive,
		ICloudStatus: iCloudStatusFromSession(session),
		CreatedAt:    now,
		UpdatedAt:    now,
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
	account.Status = StatusActive
	account.ICloudStatus = iCloudStatusFromSession(session)
	account.UpdatedAt = time.Now()
}

func sameICloudSessionIdentity(a, b ICloudSession) bool {
	if strings.TrimSpace(a.AccountID) != "" && constantTimeEqual(a.AccountID, b.AccountID) {
		return true
	}
	if strings.TrimSpace(a.DSID) != "" && constantTimeEqual(a.DSID, b.DSID) {
		return true
	}
	if strings.TrimSpace(a.AppleID) != "" && strings.EqualFold(strings.TrimSpace(a.AppleID), strings.TrimSpace(b.AppleID)) {
		return true
	}
	return false
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
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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
	out.AppleID = firstNonEmpty(incoming.AppleID, existing.AppleID)
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
	return out
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
		SchedulerRoundIntervalSeconds: int(defaultMailboxSchedulerRoundInterval.Round(time.Second).Seconds()),
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
	if out.SchedulerRoundIntervalSeconds > 600 {
		out.SchedulerRoundIntervalSeconds = 600
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
