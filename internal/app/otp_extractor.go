package app

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
)

const maxOTPHTMLTextBytes = 256 << 10

var scoredOTPCandidateRegex = regexp.MustCompile(`[0-9]{3}[ \t-][0-9]{3}|[A-Za-z0-9]{2,10}(?:-[A-Za-z0-9]{2,10}){1,2}|[A-Za-z0-9]{4,10}`)

type otpExtraction struct {
	Code       string
	Confidence int
	Language   string
	Rule       string
	Source     string
	Ambiguous  bool
}

type otpTextSource struct {
	name  string
	text  string
	bonus int
}

type scoredOTPCandidate struct {
	code        string
	score       int
	language    string
	rule        string
	source      string
	occurrences int
}

// extractOTP keeps the established call contract while using the scored,
// ambiguity-aware extractor. Call extractOTPFromParts when the HTML body is
// available so style/script/hidden content can be excluded safely.
func extractOTP(text string) string {
	return extractOTPFromParts("", text, "").Code
}

func extractOTPFromMessage(msg Message) otpExtraction {
	return extractOTPFromParts(msg.Subject, msg.Body, msg.HTMLBody)
}

func extractOTPFromParts(subject, body, htmlBody string) otpExtraction {
	sources := make([]otpTextSource, 0, 3)
	if value := strings.TrimSpace(subject); value != "" {
		sources = append(sources, otpTextSource{name: "subject", text: value, bonus: 80})
	}
	if value := strings.TrimSpace(body); value != "" {
		sources = append(sources, otpTextSource{name: "plain_text", text: value, bonus: 30})
	}
	if value := strings.TrimSpace(visibleEmailHTMLText(htmlBody)); value != "" {
		sources = append(sources, otpTextSource{name: "html_visible_text", text: value, bonus: 25})
	}
	if len(sources) == 0 {
		return otpExtraction{}
	}

	byCode := make(map[string]*scoredOTPCandidate)
	for _, source := range sources {
		text := normalizeOTPText(source.text)
		keywords := otpKeywordRegex.FindAllStringIndex(text, -1)
		matches := scoredOTPCandidateRegex.FindAllStringIndex(text, -1)
		for _, match := range matches {
			start, end := match[0], match[1]
			if looksLikeOTPMetadata(text, start) {
				continue
			}
			code := normalizedContextualOTP(text[start:end])
			if code == "" {
				continue
			}

			base, kind := otpCandidateBaseScore(code)
			keywordScore, language, hasKeyword := nearestOTPKeyword(text, start, end, keywords)
			if looksLikeContextualDate(text, 0, start, end) && !(hasKeyword && len(code) == 4) {
				continue
			}
			if !hasKeyword && !isSixDigitOTP(code) {
				continue
			}
			score := base + source.bonus + keywordScore
			if hasDirectOTPSeparator(text, start) {
				score += 25
			}
			rule := "邮件中唯一的6位数字"
			if hasKeyword {
				rule = "验证码关键词附近的" + kind
			}

			current := byCode[code]
			if current == nil {
				byCode[code] = &scoredOTPCandidate{
					code: code, score: score, language: language, rule: rule,
					source: source.name, occurrences: 1,
				}
				continue
			}
			current.occurrences++
			if score > current.score {
				current.score = score
				current.language = language
				current.rule = rule
				current.source = source.name
			}
		}
	}

	candidates := make([]*scoredOTPCandidate, 0, len(byCode))
	for _, candidate := range byCode {
		candidate.score += min(candidate.occurrences-1, 3) * 18
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return otpExtraction{}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].code < candidates[j].code
	})
	top := candidates[0]
	if len(candidates) > 1 && top.score-candidates[1].score < 45 {
		return otpExtraction{Confidence: otpConfidence(top.score), Ambiguous: true}
	}
	if top.score < 420 {
		return otpExtraction{Confidence: otpConfidence(top.score), Ambiguous: true}
	}
	return otpExtraction{
		Code: top.code, Confidence: otpConfidence(top.score), Language: top.language,
		Rule: top.rule, Source: top.source,
	}
}

func otpCandidateBaseScore(code string) (int, string) {
	compact := strings.ReplaceAll(code, "-", "")
	isNumeric := strings.IndexFunc(compact, func(r rune) bool { return r < '0' || r > '9' }) < 0
	hasDigit := strings.IndexFunc(compact, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0
	switch {
	case isNumeric && len(compact) == 6:
		return 420, "6位数字"
	case isNumeric:
		return 310, "数字验证码"
	case hasDigit:
		return 300, "字母数字混合验证码"
	default:
		return 220, "分段字母验证码"
	}
}

func isSixDigitOTP(code string) bool {
	if len(code) != 6 {
		return false
	}
	return strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func nearestOTPKeyword(text string, candidateStart, candidateEnd int, keywords [][]int) (int, string, bool) {
	bestScore, bestLanguage := 0, "und"
	for _, keyword := range keywords {
		score := 0
		if candidateStart >= keyword[1] {
			distance := utf8.RuneCountInString(text[keyword[1]:candidateStart])
			if distance <= 160 {
				score = 180 - min(distance, 160)
			}
		} else if candidateEnd <= keyword[0] {
			distance := utf8.RuneCountInString(text[candidateEnd:keyword[0]])
			if distance <= 100 {
				score = 125 - min(distance, 100)
			}
		}
		if score > bestScore {
			bestScore = score
			bestLanguage = otpKeywordLanguage(text[keyword[0]:keyword[1]])
		}
	}
	return bestScore, bestLanguage, bestScore > 0
}

func hasDirectOTPSeparator(text string, candidateStart int) bool {
	if candidateStart <= 0 {
		return false
	}
	prefix := strings.TrimSpace(text[max(0, candidateStart-8):candidateStart])
	return strings.HasSuffix(prefix, ":") || strings.HasSuffix(prefix, "：") || strings.HasSuffix(prefix, "=")
}

func otpConfidence(score int) int {
	switch {
	case score >= 650:
		return 99
	case score >= 590:
		return 97
	case score >= 540:
		return 94
	case score >= 500:
		return 91
	case score >= 460:
		return 86
	case score >= 420:
		return 78
	case score >= 380:
		return 68
	default:
		return 55
	}
}

func otpKeywordLanguage(keyword string) string {
	lower := strings.ToLower(keyword)
	switch {
	case strings.ContainsAny(lower, "認証確認検証ワンタイム"):
		return "ja"
	case strings.ContainsAny(lower, "인증확인보안일회용"):
		return "ko"
	case strings.ContainsAny(lower, "验证码驗證碼校验碼動態碼安全碼登录碼登錄碼代碼"):
		return "zh"
	case strings.ContainsAny(lower, "सत्यापनपुष्टिसुरक्षाओटीपी"):
		return "hi"
	case strings.ContainsAny(lower, "رمزالتحققالتأكيدالأمانكلمةالمرور"):
		return "ar"
	case strings.ContainsAny(lower, "รหัสยืนยันตรวจสอบความปลอดภัย"):
		return "th"
	case strings.ContainsAny(lower, "кодподтвержденияпроверкибезопасностиодноразовыйпароль"):
		return "ru"
	case strings.Contains(lower, "mã ") || strings.Contains(lower, "xác "):
		return "vi"
	case strings.Contains(lower, "verificación"):
		return "es"
	case strings.Contains(lower, "vérification"):
		return "fr"
	case strings.Contains(lower, "verificação"):
		return "pt"
	case strings.Contains(lower, "bestätigung") || strings.Contains(lower, "verifizierung"):
		return "de"
	case strings.Contains(lower, "verifikasi"):
		return "id"
	case strings.Contains(lower, "verifica"):
		return "it"
	case strings.Contains(lower, "doğrulama"):
		return "tr"
	default:
		return "en"
	}
}

func visibleEmailHTMLText(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	doc, err := xhtml.Parse(strings.NewReader(raw))
	if err != nil {
		return ""
	}
	var builder strings.Builder
	var walk func(*xhtml.Node, bool)
	walk = func(node *xhtml.Node, hidden bool) {
		if builder.Len() >= maxOTPHTMLTextBytes {
			return
		}
		if node.Type == xhtml.ElementNode {
			tag := strings.ToLower(node.Data)
			if hidden || hiddenEmailHTMLNode(node) || tag == "script" || tag == "style" || tag == "noscript" || tag == "template" || tag == "head" || tag == "svg" {
				return
			}
			if isEmailHTMLBlock(tag) {
				builder.WriteByte('\n')
			}
		}
		if node.Type == xhtml.TextNode {
			value := strings.Join(strings.Fields(node.Data), " ")
			if value != "" {
				writeBoundedOTPHTMLText(&builder, value)
				writeBoundedOTPHTMLText(&builder, " ")
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, hidden)
		}
		if node.Type == xhtml.ElementNode && isEmailHTMLBlock(strings.ToLower(node.Data)) {
			builder.WriteByte('\n')
		}
	}
	walk(doc, false)
	value := builder.String()
	if len(value) > maxOTPHTMLTextBytes {
		value = value[:maxOTPHTMLTextBytes]
		for value != "" && !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return strings.TrimSpace(value)
}

func writeBoundedOTPHTMLText(builder *strings.Builder, value string) {
	remaining := maxOTPHTMLTextBytes - builder.Len()
	if remaining <= 0 || value == "" {
		return
	}
	if len(value) > remaining {
		value = value[:remaining]
		for value != "" && !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	builder.WriteString(value)
}

func hiddenEmailHTMLNode(node *xhtml.Node) bool {
	for _, attr := range node.Attr {
		key, value := strings.ToLower(attr.Key), strings.ToLower(strings.TrimSpace(attr.Val))
		switch key {
		case "hidden":
			return true
		case "aria-hidden":
			if value == "true" {
				return true
			}
		case "style":
			compact := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(value)
			if strings.Contains(compact, "display:none") || strings.Contains(compact, "visibility:hidden") || strings.Contains(compact, "font-size:0") {
				return true
			}
		}
	}
	return false
}

func isEmailHTMLBlock(tag string) bool {
	switch tag {
	case "br", "p", "div", "section", "article", "header", "footer", "li", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre":
		return true
	default:
		return false
	}
}
