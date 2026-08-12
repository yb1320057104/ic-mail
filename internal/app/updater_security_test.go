package app

import (
	"context"
	"strings"
	"testing"
)

func TestUpdaterRejectsMissingOrMalformedChecksumBeforeDownload(t *testing.T) {
	for _, checksum := range []string{"", strings.Repeat("z", 64)} {
		err := downloadAndReplaceExecutable(context.Background(), "http://127.0.0.1:1/update", checksum, "unused")
		if err == nil || !strings.Contains(err.Error(), "SHA-256") {
			t.Fatalf("checksum=%q err=%v", checksum, err)
		}
	}
}
