package app

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"
)

const captchaAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

type captchaChallenge struct {
	answer    string
	svg       string
	expiresAt time.Time
}

type captchaStore struct {
	mu    sync.Mutex
	items map[string]captchaChallenge
}

func newCaptchaStore() *captchaStore { return &captchaStore{items: make(map[string]captchaChallenge)} }

func (s *captchaStore) create() (string, string, error) {
	id, err := randomToken(18)
	if err != nil {
		return "", "", err
	}
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	code := make([]byte, len(buf))
	for i, b := range buf {
		code[i] = captchaAlphabet[int(b)%len(captchaAlphabet)]
	}
	svg := captchaSVG(string(code), buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, item := range s.items {
		if !item.expiresAt.After(now) {
			delete(s.items, key)
		}
	}
	s.items[id] = captchaChallenge{answer: normalizeCaptchaAnswer(string(code)), svg: svg, expiresAt: now.Add(5 * time.Minute)}
	return id, svg, nil
}

func (s *captchaStore) image(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	return item.svg, ok && item.expiresAt.After(time.Now())
}

func (s *captchaStore) verify(id, answer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	delete(s.items, id)
	if !ok || !item.expiresAt.After(time.Now()) {
		return false
	}
	return constantTimeEqual(normalizeCaptchaAnswer(answer), item.answer)
}

func normalizeCaptchaAnswer(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
}

func captchaSVG(code string, noise []byte) string {
	lines := ""
	for i := 0; i < 7; i++ {
		x1, y1 := int(noise[i%len(noise)])%180, int(noise[(i+1)%len(noise)])%54
		x2, y2 := (x1+45+i*17)%180, (y1+19+i*9)%54
		lines += fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d"/>`, x1, y1, x2, y2)
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="180" height="54" viewBox="0 0 180 54"><rect width="180" height="54" rx="10" fill="#effaf8"/><g stroke="#7dd3c7" stroke-width="1" opacity=".65">%s</g><text x="90" y="37" text-anchor="middle" font-family="Consolas,monospace" font-size="28" font-weight="800" letter-spacing="8" fill="#0f766e" transform="rotate(-2 90 27)">%s</text></svg>`, lines, code)
}
