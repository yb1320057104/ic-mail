package app

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestIMAPWaitForExistsAcceptsEventBeforeIdleContinuation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverErr := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(server)
		command, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if command != "A003 IDLE\r\n" {
			serverErr <- fmt.Errorf("IDLE command = %q", command)
			return
		}
		if _, err := fmt.Fprint(server, "* 31 EXISTS\r\n+ idling\r\n"); err != nil {
			serverErr <- err
			return
		}
		done, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if done != "DONE\r\n" {
			serverErr <- fmt.Errorf("DONE command = %q", done)
			return
		}
		_, err = fmt.Fprint(server, "A003 OK IDLE completed\r\n")
		serverErr <- err
	}()

	if err := imapWaitForExists(context.Background(), client, bufio.NewReader(client), "A003"); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDecodeMIMEHeaderAcceptsUTF8Alias(t *testing.T) {
	got := decodeMIMEHeader(`=?UTF8?B?5p2o5Y2a?= <sender@example.com>`)
	if got != `杨博 <sender@example.com>` {
		t.Fatalf("decoded header = %q", got)
	}
}

func TestIMAPSelectErrorExplainsUnsafeLogin(t *testing.T) {
	err := imapSelectError("imap.188.com", "A002 NO SELECT Unsafe Login. Please contact kefu@188.com for help")
	message := err.Error()
	for _, want := range []string{"邮箱服务商风控", "imap.188.com", "Unsafe Login", "客户端授权码"} {
		if !strings.Contains(message, want) {
			t.Fatalf("unsafe login message = %q, want contains %q", message, want)
		}
	}
}

func TestIMAPSelectErrorUsesActualHost(t *testing.T) {
	err := imapSelectError("imap.example.com", "A002 NO mailbox unavailable")
	if strings.Contains(err.Error(), "iCloud") || !strings.Contains(err.Error(), "imap.example.com") {
		t.Fatalf("select message = %q", err.Error())
	}
}

func TestICloudIMAPMessagesByMailboxMatchesRecipientAlias(t *testing.T) {
	receivedAt := time.Date(2026, 7, 1, 5, 2, 50, 0, time.UTC)
	mailboxes := []Mailbox{
		{ID: "mbx_match", Email: "alias-one@icloud.com"},
		{ID: "mbx_other", Email: "alias-two@icloud.com"},
	}
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: alias-one@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: " + receivedAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 246810\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "42", Raw: []byte(raw)}}, mailboxes, receivedAt.Add(-time.Minute), "ChatGPT")
	messages := got["mbx_match"]
	if len(messages) != 1 {
		t.Fatalf("matched messages = %d, want 1; got=%+v", len(messages), got)
	}
	if code := extractOTP(messages[0].Subject + "\n" + messages[0].Body); code != "246810" {
		t.Fatalf("code = %q, want 246810; message=%+v", code, messages[0])
	}
	if messages[0].RemoteID != "imap:42" || messages[0].UID != "42" {
		t.Fatalf("remote id/uid = %q/%q, want imap:42/42", messages[0].RemoteID, messages[0].UID)
	}
	if len(got["mbx_other"]) != 0 {
		t.Fatalf("wrong alias received messages: %+v", got["mbx_other"])
	}
}

func TestICloudIMAPMessagePreservesHTMLAndPlainText(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_html", Email: "alias-html@icloud.com"}}
	raw := "From: ChatGPT <noreply@example.com>\r\n" +
		"To: alias-html@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT login code\r\n" +
		"Content-Type: multipart/alternative; boundary=mail-boundary\r\n\r\n" +
		"--mail-boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour code is 691288\r\n" +
		"--mail-boundary\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>Your code</h1><strong>691288</strong></body></html>\r\n" +
		"--mail-boundary--\r\n"
	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "88", Raw: []byte(raw)}}, mailboxes, time.Time{}, "")
	messages := got["mbx_html"]
	if len(messages) != 1 {
		t.Fatalf("messages=%+v", messages)
	}
	if !strings.Contains(messages[0].Body, "691288") || !strings.Contains(messages[0].HTMLBody, "<strong>691288</strong>") {
		t.Fatalf("plain/html body not preserved: %+v", messages[0])
	}
}

func TestICloudIMAPVisualSyncKeepsOrdinaryAliasMail(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_visual", Email: "37cutouts-tepee@icloud.com"}}
	raw := "From: Tester <sender@example.com>\r\n" +
		"To: Hide My Email <37cutouts-tepee@icloud.com>\r\n" +
		"X-ICLOUD-HME: p=37cutouts-tepee@icloud.com; f=receiver@qq.com; r=to\r\n" +
		"Subject: 测试\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"13313\r\n"
	fetched := []iCloudIMAPFetchedMessage{{UID: "3140", Raw: []byte(raw)}}
	visual := iCloudIMAPMessagesByMailbox(fetched, mailboxes, time.Time{}, "")
	if len(visual["mbx_visual"]) != 1 {
		t.Fatalf("visual sync dropped ordinary alias mail: %+v", visual)
	}
	codeOnly := iCloudIMAPMessagesByMailbox(fetched, mailboxes, time.Time{}, "OpenAI")
	if len(codeOnly["mbx_visual"]) != 0 {
		t.Fatalf("code sync accepted ordinary non-code mail: %+v", codeOnly)
	}
}

func TestICloudIMAPVisualSyncRecoversMessageSkippedBeforeLastSync(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	receivedAt := now.Add(-10 * time.Minute)
	mailboxes := []Mailbox{{ID: "mbx_recover", Email: "recover@icloud.com", LastSyncAt: now}}
	raw := "From: Service <noreply@example.com>\r\n" +
		"To: recover@icloud.com\r\n" +
		"Subject: Older message\r\n" +
		"Date: " + receivedAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"This message was skipped by an older recognizer.\r\n"
	got := iCloudIMAPMessagesByMailbox(
		[]iCloudIMAPFetchedMessage{{UID: "3150", Raw: []byte(raw)}},
		mailboxes,
		now.Add(-time.Hour),
		"",
	)
	if len(got["mbx_recover"]) != 1 {
		t.Fatalf("visual recovery dropped message older than LastSyncAt: %+v", got)
	}
}

func TestICloudIMAPCodeSyncRecognizesArabicHTML(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_arabic", Email: "arabic@icloud.com"}}
	raw := "From: Service <noreply@example.com>\r\n" +
		"To: arabic@icloud.com\r\n" +
		"Subject: تسجيل الدخول\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n\r\n" +
		`<html><head><style>.code-111111{color:red}</style></head><body><p>أدخل كود المصادقة المؤقت هذا للمتابعة: <strong>٦٩١٢٨٨</strong></p></body></html>`
	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "3151", Raw: []byte(raw)}}, mailboxes, time.Time{}, "OpenAI")
	messages := got["mbx_arabic"]
	if len(messages) != 1 {
		t.Fatalf("Arabic HTML verification mail was filtered before storage: %+v", got)
	}
	if details := extractOTPFromParts(messages[0].Subject, messages[0].Body, messages[0].HTMLBody); details.Code != "691288" {
		t.Fatalf("Arabic HTML code=%q details=%+v", details.Code, details)
	}
}

func TestICloudIMAPMatchesArabicForwardedRecipientLabel(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_arabic_recipient", Email: "arabic-alias@icloud.com"}}
	raw := "To: destination@example.com\r\n" +
		"From: Service <noreply@example.com>\r\n" +
		"Subject: تسجيل الدخول\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"إلى: Arabic User <arabic-alias@icloud.com>\nأدخل كود المصادقة المؤقت هذا للمتابعة: 691288"
	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "3152", Raw: []byte(raw)}}, mailboxes, time.Time{}, "OpenAI")
	if len(got["mbx_arabic_recipient"]) != 1 {
		t.Fatalf("Arabic forwarded recipient should match alias: %+v", got)
	}
}

func TestICloudIMAPMessagesByMailboxMatchesMultipleRecipientAliases(t *testing.T) {
	firstAt := time.Date(2026, 7, 1, 5, 2, 50, 0, time.UTC)
	secondAt := firstAt.Add(20 * time.Second)
	mailboxes := []Mailbox{
		{ID: "mbx_one", Email: "alias-one@icloud.com"},
		{ID: "mbx_two", Email: "alias-two@icloud.com"},
	}
	rawOne := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: alias-one@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: " + firstAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 111111\r\n"
	rawTwo := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: alias-two@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: " + secondAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 222222\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{
		{UID: "101", Raw: []byte(rawOne)},
		{UID: "102", Raw: []byte(rawTwo)},
	}, mailboxes, time.Time{}, "ChatGPT")

	if messages := got["mbx_one"]; len(messages) != 1 || extractOTP(messages[0].Subject+"\n"+messages[0].Body) != "111111" {
		t.Fatalf("mbx_one messages = %+v, want one message with code 111111", messages)
	}
	if messages := got["mbx_two"]; len(messages) != 1 || extractOTP(messages[0].Subject+"\n"+messages[0].Body) != "222222" {
		t.Fatalf("mbx_two messages = %+v, want one message with code 222222", messages)
	}
}

func TestICloudIMAPMessagesByMailboxIgnoresIMAPLoginEmail(t *testing.T) {
	receivedAt := time.Date(2026, 7, 1, 5, 2, 50, 0, time.UTC)
	mailboxes := []Mailbox{
		{ID: "mbx_login", Email: "owner@icloud.com"},
		{ID: "mbx_alias", Email: "alias-one@icloud.com"},
	}
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: alias-one@icloud.com\r\n" +
		"Delivered-To: owner@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: " + receivedAt.Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 333333\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "103", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT", "owner@icloud.com")
	if messages := got["mbx_alias"]; len(messages) != 1 || extractOTP(messages[0].Subject+"\n"+messages[0].Body) != "333333" {
		t.Fatalf("alias messages = %+v, want one message with code 333333", messages)
	}
	if len(got["mbx_login"]) != 0 {
		t.Fatalf("login mailbox should be ignored, got=%+v", got["mbx_login"])
	}
}

func TestICloudIMAPMessagesByMailboxIgnoresWrongAlias(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_target", Email: "target@icloud.com"}}
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: someone-else@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: Wed, 01 Jul 2026 05:02:50 +0000\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 135790\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "51", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT")
	if len(got["mbx_target"]) != 0 {
		t.Fatalf("wrong alias should not match, got=%+v", got["mbx_target"])
	}
}

func TestICloudIMAPMessagesByMailboxIgnoresAliasMentionedOnlyInBody(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_target", Email: "target@icloud.com"}}
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: someone-else@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Date: Wed, 01 Jul 2026 05:02:50 +0000\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Enter this temporary verification code to continue: 975310\r\n" +
		"This message mentions target@icloud.com in the body only.\r\n"

	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "52", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT")
	if len(got["mbx_target"]) != 0 {
		t.Fatalf("alias mentioned only in body should not match, got=%+v", got["mbx_target"])
	}
}

func TestIMAPLineHasExistsEvent(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{line: "* 123 EXISTS", want: true},
		{line: "* 1 RECENT", want: false},
		{line: "A001 OK IDLE completed", want: false},
		{line: "* 123 FETCH (UID 9)", want: false},
	}
	for _, tc := range cases {
		if got := imapLineHasExistsEvent(tc.line); got != tc.want {
			t.Fatalf("imapLineHasExistsEvent(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestIMAPSearchCommandUsesUIDCursorWhenAvailable(t *testing.T) {
	command := imapSearchCommand(LoginState{}, []Mailbox{
		{Email: "one@icloud.com", LastSyncUID: "542"},
		{Email: "two@icloud.com", LastSyncUID: "imap:550"},
	}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if command != "UID SEARCH UID 43:*" {
		t.Fatalf("imapSearchCommand with cursors = %q, want UID SEARCH UID 43:*", command)
	}
}

func TestIMAPSearchCommandPrefersAccountCursor(t *testing.T) {
	command := imapSearchCommand(LoginState{IMAPLastSyncUID: "600"}, []Mailbox{
		{Email: "one@icloud.com"},
		{Email: "two@icloud.com", LastSyncUID: "42"},
	}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if command != "UID SEARCH UID 101:*" {
		t.Fatalf("imapSearchCommand account cursor = %q, want UID SEARCH UID 101:*", command)
	}
}

func TestIMAPUIDsForSyncDoesNotSkipBusyInboxBacklog(t *testing.T) {
	uids := make([]int, 0, 520)
	for uid := 101; uid <= 620; uid++ {
		uids = append(uids, uid)
	}
	selected, cursor := imapUIDsForSync(uids, 600, 8)
	if got := fmt.Sprint(selected); got != "[601 602 603 604 605 606 607 608]" {
		t.Fatalf("selected = %s", got)
	}
	if cursor != "608" {
		t.Fatalf("cursor = %q, want 608", cursor)
	}
}

func TestIMAPUIDsForSyncUsesSpareBudgetForOverlap(t *testing.T) {
	selected, cursor := imapUIDsForSync([]int{595, 596, 597, 598, 599, 600, 601, 602}, 600, 5)
	if got := fmt.Sprint(selected); got != "[598 599 600 601 602]" {
		t.Fatalf("selected = %s", got)
	}
	if cursor != "602" {
		t.Fatalf("cursor = %q, want 602", cursor)
	}
}

func TestICloudIMAPMessagesByMailboxMatchesForwardedRecipientLine(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_forwarded", Email: "private-alias@icloud.com"}}
	raw := "To: destination@qq.com\r\n" +
		"From: ChatGPT <noreply@example.com>\r\n" +
		"Subject: Your verification code 123456\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"转发邮件\n收件人：private-alias@icloud.com\n验证码 123456"
	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "88", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT")
	if len(got["mbx_forwarded"]) != 1 {
		t.Fatalf("forwarded recipient should match alias, got=%+v", got)
	}
}

func TestICloudIMAPMessagesByMailboxKeepsPlusAliasesIsolated(t *testing.T) {
	mailboxes := []Mailbox{
		{ID: "parent", Email: "isolation@icloud.com"},
		{ID: "alias-one", Email: "isolation+one@icloud.com", MailboxType: "alias", ParentMailboxID: "parent"},
		{ID: "alias-two", Email: "isolation+two@icloud.com", MailboxType: "alias", ParentMailboxID: "parent"},
	}
	raw := "To: isolation+one@icloud.com\r\nFrom: OpenAI <noreply@example.com>\r\nSubject: Verification code 123456\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour code is 123456"
	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "alias-1", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT")
	if len(got["alias-one"]) != 1 || len(got["alias-two"]) != 0 || len(got["parent"]) != 0 {
		t.Fatalf("plus alias message leaked between mailboxes: %+v", got)
	}
}

func TestICloudIMAPMessagesByMailboxMatchesHTMLForwardedRecipient(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_html", Email: "html-alias@icloud.com"}}
	raw := "To: destination@qq.com\r\nFrom: ChatGPT <noreply@example.com>\r\nSubject: Verification code 654321\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
		"<table><tr><td>收件人：</td><td>HTML User &lt;html-alias@icloud.com&gt;</td></tr></table><p>验证码 654321</p>"
	_, evidence, parsed := parseICloudIMAPMessage(iCloudIMAPFetchedMessage{UID: "89", Raw: []byte(raw)})
	if !parsed || !strings.Contains(strings.ToLower(evidence), "html-alias@icloud.com") {
		t.Fatalf("HTML recipient evidence missing: parsed=%t evidence=%q", parsed, evidence)
	}
	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "89", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT")
	if len(got["mbx_html"]) != 1 {
		t.Fatalf("HTML forwarded recipient should match alias, got=%+v", got)
	}
}

func TestICloudIMAPMessagesByMailboxMatchesRFC822ForwardedRecipient(t *testing.T) {
	mailboxes := []Mailbox{{ID: "mbx_rfc822", Email: "attached-alias@icloud.com"}}
	raw := "To: destination@qq.com\r\nFrom: Forwarder <forward@example.com>\r\nSubject: Fwd: ChatGPT verification code\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\nContent-Type: text/plain\r\n\r\nForwarded message\r\n" +
		"--outer\r\nContent-Type: message/rfc822\r\n\r\n" +
		"To: attached-alias@icloud.com\r\nFrom: ChatGPT <noreply@example.com>\r\nSubject: Verification code 246810\r\nContent-Type: text/plain\r\n\r\nYour code is 246810\r\n" +
		"--outer--\r\n"
	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{UID: "90", Raw: []byte(raw)}}, mailboxes, time.Time{}, "ChatGPT")
	if len(got["mbx_rfc822"]) != 1 {
		t.Fatalf("RFC822 forwarded recipient should match alias, got=%+v", got)
	}
}

func TestIMAPSelectUIDNextLastUID(t *testing.T) {
	lines := []string{
		"* 652 EXISTS",
		"* OK [UIDVALIDITY 1] UIDs valid",
		"* OK [UIDNEXT 88291] Predicted next UID",
		"A002 OK [READ-WRITE] SELECT completed",
	}
	if got := imapSelectLastUID(lines); got != 88290 {
		t.Fatalf("imapSelectLastUID() = %d, want 88290", got)
	}
}

func TestIMAPSearchCommandFallsBackToSinceWhenCursorMissing(t *testing.T) {
	after := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	command := imapSearchCommand(LoginState{}, []Mailbox{
		{Email: "one@icloud.com", LastSyncUID: "42"},
		{Email: "two@icloud.com"},
	}, after)
	if command != "UID SEARCH SINCE 1-Jul-2026" {
		t.Fatalf("imapSearchCommand without all cursors = %q, want SINCE fallback", command)
	}
}

func TestICloudIMAPDialerUsesFallbackResolver(t *testing.T) {
	dialer := newICloudIMAPDialer("imap.mail.me.com")
	if dialer.NetDialer == nil {
		t.Fatal("imap dialer NetDialer is nil")
	}
	if dialer.NetDialer.Resolver == nil {
		t.Fatal("imap dialer Resolver is nil, want public DNS fallback")
	}
	if dialer.NetDialer.Timeout != 15*time.Second {
		t.Fatalf("imap dialer timeout = %s, want 15s", dialer.NetDialer.Timeout)
	}
	if dialer.Config == nil || dialer.Config.ServerName != "imap.mail.me.com" {
		t.Fatalf("imap dialer TLS config = %+v", dialer.Config)
	}
}

func TestDNSFallbackNetworksPreferTCPBeforeUDP(t *testing.T) {
	got := dnsFallbackNetworks("udp6")
	want := []string{"tcp", "udp"}
	if len(got) != len(want) {
		t.Fatalf("dnsFallbackNetworks length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dnsFallbackNetworks(%q)[%d] = %q, want %q", "udp6", i, got[i], want[i])
		}
	}
}

func TestDNSParseAResponse(t *testing.T) {
	const id uint16 = 0x1234
	query, err := dnsBuildAQuery("imap.mail.me.com", id)
	if err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(response[0:2], id)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, query[12:]...)
	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint32(response, 60)
	response = binary.BigEndian.AppendUint16(response, 4)
	response = append(response, 17, 57, 152, 32)

	ips, err := dnsParseAResponse(response, id)
	if err != nil {
		t.Fatal(err)
	}
	want := net.IPv4(17, 57, 152, 32).String()
	if len(ips) != 1 || ips[0].String() != want {
		t.Fatalf("dnsParseAResponse = %v, want %s", ips, want)
	}
}

func TestAppendUniqueIPv4(t *testing.T) {
	got := appendUniqueIPv4(
		[]net.IP{net.IPv4(17, 57, 152, 32), net.ParseIP("2001:db8::1")},
		net.IPv4(17, 57, 152, 32),
		net.IPv4(17, 57, 152, 35),
	)
	if len(got) != 2 {
		t.Fatalf("appendUniqueIPv4 length = %d, want 2: %v", len(got), got)
	}
	if got[0].String() != "17.57.152.32" || got[1].String() != "17.57.152.35" {
		t.Fatalf("appendUniqueIPv4 order = %v", got)
	}
}
func TestIMAPLooksLikeJunkMailbox(t *testing.T) {
	for _, name := range []string{"Junk", "INBOX.Junk", "Spam", "Junk E-mail", "垃圾邮件", "垃圾箱"} {
		if !imapLooksLikeJunkMailbox(name) {
			t.Fatalf("expected junk mailbox %q", name)
		}
	}
	for _, name := range []string{"INBOX", "Sent", "Drafts", "Archive", "Notes"} {
		if imapLooksLikeJunkMailbox(name) {
			t.Fatalf("did not expect junk mailbox %q", name)
		}
	}
}

func TestIMAPListedJunkMailboxesParsesLIST(t *testing.T) {
	got := imapListedJunkMailboxes([]string{
		`* LIST (\HasNoChildren) "/" INBOX`,
		`* LIST (\HasNoChildren) "/" Junk`,
		`* LIST (\HasNoChildren) "/" "Junk E-mail"`,
		`* LIST (\HasNoChildren) "/" Sent`,
		`A005 OK LIST completed`,
	})
	if len(got) != 2 || got[0] != "Junk" || got[1] != "Junk E-mail" {
		t.Fatalf("listed junk mailboxes = %#v", got)
	}
}

func TestICloudIMAPJunkMessageUsesFolderRemoteID(t *testing.T) {
	raw := "From: OpenAI <noreply@tm.openai.com>\r\n" +
		"To: junk-alias@icloud.com\r\n" +
		"Subject: Your temporary ChatGPT verification code\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"Enter this temporary verification code to continue: 246810\r\n"
	got := iCloudIMAPMessagesByMailbox([]iCloudIMAPFetchedMessage{{
		UID:    "42",
		Raw:    []byte(raw),
		Folder: "Junk",
	}}, []Mailbox{{ID: "mbx_junk", Email: "junk-alias@icloud.com"}}, time.Time{}, "ChatGPT")
	messages := got["mbx_junk"]
	if len(messages) != 1 {
		t.Fatalf("junk messages = %+v", got)
	}
	if messages[0].RemoteID != "imap:Junk:42" {
		t.Fatalf("junk remote id = %q, want imap:Junk:42", messages[0].RemoteID)
	}
	if messages[0].UID != "" {
		t.Fatalf("junk UID should not advance inbox cursor, got %q", messages[0].UID)
	}
	if imapUIDNumber(messages[0].RemoteID) != 0 {
		t.Fatalf("junk remote id should not parse as inbox UID: %q", messages[0].RemoteID)
	}
}

func TestJunkLimitForKeepsRecentFilteredMail(t *testing.T) {
	if got := junkLimitFor(8); got != 20 {
		t.Fatalf("junkLimitFor(8)=%d, want 20", got)
	}
	if got := junkLimitFor(50); got != 40 {
		t.Fatalf("junkLimitFor(50)=%d, want 40", got)
	}
}

func TestIsICloudIMAPHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"imap.mail.me.com", true},
		{"imap.mail.me.com.", true},
		{"IMAP.MAIL.ME.COM", true},
		{"", true}, // empty defaults to iCloud host
		{"imap.icloud.com", true},
		{"imap.mail.icloud.com.cn", true},
		{"imap.qq.com", false},
		{"imap.163.com", false},
		{"imap.gmail.com", false},
		{"imap.126.com", false},
	}
	for _, tc := range cases {
		if got := isICloudIMAPHost(tc.host); got != tc.want {
			t.Errorf("isICloudIMAPHost(%q)=%v want %v", tc.host, got, tc.want)
		}
	}
}
