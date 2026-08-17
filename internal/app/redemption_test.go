package app

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRedemptionPoolRedeemAndRotate(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	owner := "user-1"
	first, err := store.AddMailboxForOwner(owner, "acc-1", "one", "one@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner(owner, "acc-1", "two", "two@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := store.RedemptionPoolForOwner(owner)
	if err != nil {
		t.Fatal(err)
	}
	healthy := map[string]bool{first.ID: true, second.ID: true}
	if n, err := store.AddRedemptionItems(owner, []string{first.ID, second.ID}, healthy); err != nil || n != 2 {
		t.Fatalf("add=%d err=%v", n, err)
	}
	code, err := store.CreateRedemptionCode(owner, 2)
	if err != nil {
		t.Fatal(err)
	}
	used, boxes, err := store.RedeemMailboxes(pool.PublicToken, code.Code, healthy)
	if err != nil {
		t.Fatal(err)
	}
	if !used.Used || len(boxes) != 2 {
		t.Fatalf("unexpected redeem: %#v %d", used, len(boxes))
	}
	if _, _, err = store.RedeemMailboxes(pool.PublicToken, code.Code, healthy); err == nil {
		t.Fatal("one-time code was accepted twice")
	}
	old := map[string]string{}
	for _, m := range boxes {
		old[m.ID] = m.APIToken
		if m.ExportedAt.IsZero() {
			t.Fatal("redeemed mailbox was not marked exported")
		}
	}
	rotated, newBoxes, err := store.RotateRedemptionCode(owner, code.Code)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RotationCount != 1 || !rotated.Invalidated || len(newBoxes) != 2 {
		t.Fatalf("unexpected rotation: %#v %d", rotated, len(newBoxes))
	}
	for _, m := range newBoxes {
		if constantTimeEqual(old[m.ID], m.APIToken) {
			t.Fatalf("token did not rotate for %s", m.ID)
		}
		if !m.ExportedAt.IsZero() {
			t.Fatalf("mailbox %s was not restored to unexported stock", m.ID)
		}
	}
	if _, _, err = store.RedeemMailboxes(pool.PublicToken, code.Code, healthy); err == nil {
		t.Fatal("invalidated code was accepted")
	}
	updatedPool, codes, items := store.RedemptionDataForOwner(owner)
	if updatedPool.RedeemedCount != 0 || !codes[0].Invalidated {
		t.Fatalf("pool/code not restored: %#v %#v", updatedPool, codes[0])
	}
	for _, item := range items {
		if !item.RedeemedAt.IsZero() || item.CodeID != "" {
			t.Fatalf("item not returned to pool: %#v", item)
		}
	}
}

func TestAliasRedemptionPoolOnlyAcceptsAliasMailboxes(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	owner := "user-alias-pool"
	parent, err := store.AddMailboxForOwner(owner, "acc-1", "主邮箱", "hake_tellers6w@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	alias, err := store.AddPlusAliasMailbox(owner, parent.ID, "hake_tellers6w+awds@icloud.com", "别名", "")
	if err != nil {
		t.Fatal(err)
	}
	healthy := map[string]bool{parent.ID: true, alias.ID: true}
	if _, err := store.AddRedemptionItems(owner, []string{alias.ID}, healthy); err == nil {
		t.Fatal("primary pool should reject alias mailbox")
	}
	n, err := store.AddAliasRedemptionItems(owner, []string{parent.ID, alias.ID}, healthy)
	if err != nil || n != 1 {
		t.Fatalf("alias pool add=%d err=%v", n, err)
	}
	_, _, items := store.RedemptionDataForOwnerType(owner, "alias")
	if len(items) != 1 || items[0].MailboxID != alias.ID {
		t.Fatalf("alias pool items = %#v", items)
	}
}

func TestRedemptionPoolDoesNotPartiallyRedeem(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.AddMailboxForOwner("u", "a", "one", "one@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	p, err := store.RedemptionPoolForOwner("u")
	if err != nil {
		t.Fatal(err)
	}
	healthy := map[string]bool{m.ID: true}
	if _, err = store.AddRedemptionItems("u", []string{m.ID}, healthy); err != nil {
		t.Fatal(err)
	}
	c, err := store.CreateRedemptionCode("u", 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.RedeemMailboxes(p.PublicToken, c.Code, healthy); err == nil {
		t.Fatal("expected insufficient stock")
	}
	updated, _ := store.FindMailboxByID(m.ID)
	if !updated.ExportedAt.IsZero() {
		t.Fatal("partial redemption marked mailbox exported")
	}
}

func TestRedeemMultipleCodesAtomically(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	owner := "batch-user"
	healthy := map[string]bool{}
	mailboxIDs := make([]string, 0, 3)
	for i, address := range []string{"batch1@icloud.com", "batch2@icloud.com", "batch3@icloud.com"} {
		m, addErr := store.AddMailboxForOwner(owner, "batch-account", string(rune('a'+i)), address)
		if addErr != nil {
			t.Fatal(addErr)
		}
		healthy[m.ID] = true
		mailboxIDs = append(mailboxIDs, m.ID)
	}
	pool, err := store.RedemptionPoolForOwner(owner)
	if err != nil {
		t.Fatal(err)
	}
	if n, addErr := store.AddRedemptionItems(owner, mailboxIDs, healthy); addErr != nil || n != 3 {
		t.Fatalf("add=%d err=%v", n, addErr)
	}
	first, err := store.CreateRedemptionCode(owner, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateRedemptionCode(owner, 2)
	if err != nil {
		t.Fatal(err)
	}

	rows, boxes, err := store.RedeemMultipleCodes(pool.PublicToken, []string{first.Code, second.Code}, healthy)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(boxes) != 3 {
		t.Fatalf("codes=%d boxes=%d", len(rows), len(boxes))
	}
	seen := map[string]bool{}
	for _, box := range boxes {
		if seen[box.ID] || box.ExportedAt.IsZero() {
			t.Fatalf("invalid batch mailbox: %#v", box)
		}
		seen[box.ID] = true
	}
}

func TestRedeemMultipleCodesRejectsWholeInvalidBatch(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.AddMailboxForOwner("batch-user", "account", "one", "one@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	healthy := map[string]bool{m.ID: true}
	pool, err := store.RedemptionPoolForOwner("batch-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AddRedemptionItems("batch-user", []string{m.ID}, healthy); err != nil {
		t.Fatal(err)
	}
	code, err := store.CreateRedemptionCode("batch-user", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.RedeemMultipleCodes(pool.PublicToken, []string{code.Code, "not-a-code"}, healthy); err == nil {
		t.Fatal("expected invalid batch to fail")
	}
	updated, _ := store.FindMailboxByID(m.ID)
	if !updated.ExportedAt.IsZero() {
		t.Fatal("invalid batch partially exported a mailbox")
	}
	_, codes, _ := store.RedemptionDataForOwner("batch-user")
	if codes[0].Used {
		t.Fatal("invalid batch partially consumed a code")
	}
	if _, _, err = store.RedeemMultipleCodes(pool.PublicToken, []string{code.Code, code.Code}, healthy); err == nil {
		t.Fatal("expected duplicate code batch to fail")
	}
}

func TestRedemptionCodePermanentAndNamedBatch(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RedemptionPoolForOwner("owner"); err != nil {
		t.Fatal(err)
	}
	permanent, err := store.CreateRedemptionCodes("owner", 1, 2, "永久批次", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range permanent {
		if code.BatchName != "永久批次" || !code.ExpiresAt.IsZero() {
			t.Fatalf("unexpected permanent code: %#v", code)
		}
	}
	timed, err := store.CreateRedemptionCodes("owner", 1, 1, "30天批次", 30)
	if err != nil {
		t.Fatal(err)
	}
	if timed[0].ExpiresAt.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Fatalf("timed code expiry is too early: %v", timed[0].ExpiresAt)
	}
	if _, err = store.CreateRedemptionCodes("owner", 1, 1, "错误批次", -1); err == nil {
		t.Fatal("negative validity was accepted")
	}
}

func TestRedemptionMailboxStaysExportLockedAfterRemoval(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner("owner", "account", "locked", "locked@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RedemptionPoolForOwner("owner"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AddRedemptionItems("owner", []string{mailbox.ID}, map[string]bool{mailbox.ID: true}); err != nil {
		t.Fatal(err)
	}
	if !store.MailboxRedemptionLocked(mailbox.ID) {
		t.Fatal("mailbox was not locked after entering redemption pool")
	}
	if _, err = store.RemoveRedemptionItems("owner", []string{mailbox.ID}); err != nil {
		t.Fatal(err)
	}
	if !store.MailboxRedemptionLocked(mailbox.ID) {
		t.Fatal("mailbox export lock was removed with redemption item")
	}
}

func TestExcludeRedemptionLockedData(t *testing.T) {
	state := State{
		Mailboxes:       []Mailbox{{ID: "normal"}, {ID: "locked-by-flag", RedemptionLocked: true}, {ID: "locked-by-item"}},
		Messages:        []Message{{ID: "m1", MailboxID: "normal"}, {ID: "m2", MailboxID: "locked-by-flag"}, {ID: "m3", MailboxID: "locked-by-item"}},
		RedemptionItems: []RedemptionItem{{MailboxID: "locked-by-item"}},
	}
	mailboxes, messages, locked := excludeRedemptionLockedData(state)
	if locked != 2 || len(mailboxes) != 1 || mailboxes[0].ID != "normal" || len(messages) != 1 || messages[0].ID != "m1" {
		t.Fatalf("unexpected filtered data: locked=%d mailboxes=%#v messages=%#v", locked, mailboxes, messages)
	}
}

func TestRotateAllMailboxAPITokens(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := store.AddMailboxForOwner("owner", "account", "first", "first@icloud.com")
	second, _ := store.AddMailboxForOwner("owner", "account", "second", "second@icloud.com")
	count, err := store.RotateAllMailboxAPITokens(180)
	if err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	updatedFirst, _ := store.FindMailboxByID(first.ID)
	updatedSecond, _ := store.FindMailboxByID(second.ID)
	if constantTimeEqual(first.APIToken, updatedFirst.APIToken) || constantTimeEqual(second.APIToken, updatedSecond.APIToken) || constantTimeEqual(updatedFirst.APIToken, updatedSecond.APIToken) {
		t.Fatal("mailbox API tokens were not independently rotated")
	}
}

func TestRedemptionOrderKeepsOriginalExportLines(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	owner := "history-owner"
	mailbox, _ := store.AddMailboxForOwner(owner, "account", "history", "history@icloud.com")
	pool, err := store.RedemptionPoolForOwner(owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.AddRedemptionItems(owner, []string{mailbox.ID}, map[string]bool{mailbox.ID: true}); err != nil {
		t.Fatal(err)
	}
	code, err := store.CreateRedemptionCode(owner, 1)
	if err != nil {
		t.Fatal(err)
	}
	used, boxes, err := store.RedeemMailboxes(pool.PublicToken, code.Code, map[string]bool{mailbox.ID: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "history@icloud.com----https://mail.example/api/v1/access/original"
	if _, err = store.CreateRedemptionOrder(pool.PublicToken, "lookup-pass", []RedemptionCode{used}, boxes, []string{want}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RotateMailboxAPIToken(mailbox.ID, 180); err != nil {
		t.Fatal(err)
	}
	orders, _, err := store.RedemptionOrdersByPassword(pool.PublicToken, "lookup-pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 1 || len(orders[0].ExportLines) != 1 || orders[0].ExportLines[0] != want {
		t.Fatalf("historical lines changed: %#v", orders)
	}
}

func TestSecondhandMailboxCanReenterAfterSevenDays(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	owner := "secondhand-owner"
	mailbox, _ := store.AddMailboxForOwner(owner, "account", "used", "used@icloud.com")
	store.mu.Lock()
	for i := range store.state.Mailboxes {
		if store.state.Mailboxes[i].ID == mailbox.ID {
			store.state.Mailboxes[i].ExportedAt = time.Now().Add(-8 * 24 * time.Hour)
		}
	}
	store.mu.Unlock()
	pool, err := store.RedemptionPoolForOwnerType(owner, "secondhand", 7)
	if err != nil {
		t.Fatal(err)
	}
	healthy := map[string]bool{mailbox.ID: true}
	if n, err := store.AddSecondhandRedemptionItems(owner, []string{mailbox.ID}, healthy); err != nil || n != 1 {
		t.Fatalf("first add=%d err=%v", n, err)
	}
	codes, err := store.CreateRedemptionCodesForPool(owner, "secondhand", 1, 1, "cycle", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, boxes, err := store.RedeemMultipleCodes(pool.PublicToken, []string{codes[0].Code}, healthy); err != nil || len(boxes) != 1 {
		t.Fatalf("redeem boxes=%d err=%v", len(boxes), err)
	}
	if _, err = store.AddSecondhandRedemptionItems(owner, []string{mailbox.ID}, healthy); err == nil {
		t.Fatal("mailbox reentered before seven-day cooldown")
	}
	store.mu.Lock()
	for i := range store.state.Mailboxes {
		if store.state.Mailboxes[i].ID == mailbox.ID {
			store.state.Mailboxes[i].ExportedAt = time.Now().Add(-8 * 24 * time.Hour)
		}
	}
	store.mu.Unlock()
	if n, err := store.AddSecondhandRedemptionItems(owner, []string{mailbox.ID}, healthy); err != nil || n != 1 {
		t.Fatalf("second add=%d err=%v", n, err)
	}
}

func TestRotatedSecondhandMailboxStartsNewCooldown(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	owner := "secondhand-rotate-owner"
	mailbox, _ := store.AddMailboxForOwner(owner, "account", "used", "rotate-used@icloud.com")
	store.mu.Lock()
	for i := range store.state.Mailboxes {
		if store.state.Mailboxes[i].ID == mailbox.ID {
			store.state.Mailboxes[i].ExportedAt = time.Now().Add(-8 * 24 * time.Hour)
		}
	}
	store.mu.Unlock()
	pool, err := store.RedemptionPoolForOwnerType(owner, "secondhand", 7)
	if err != nil {
		t.Fatal(err)
	}
	healthy := map[string]bool{mailbox.ID: true}
	if _, err = store.AddSecondhandRedemptionItems(owner, []string{mailbox.ID}, healthy); err != nil {
		t.Fatal(err)
	}
	codes, err := store.CreateRedemptionCodesForPool(owner, "secondhand", 1, 1, "rotate", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.RedeemMultipleCodes(pool.PublicToken, []string{codes[0].Code}, healthy); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.RotateRedemptionCode(owner, codes[0].Code); err != nil {
		t.Fatal(err)
	}
	updated, _ := store.FindMailboxByID(mailbox.ID)
	if updated.ExportedAt.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("rotation did not start a new cooldown: %v", updated.ExportedAt)
	}
	if _, err = store.AddSecondhandRedemptionItems(owner, []string{mailbox.ID}, healthy); err == nil {
		t.Fatal("rotated secondhand mailbox reentered before cooldown")
	}
}
