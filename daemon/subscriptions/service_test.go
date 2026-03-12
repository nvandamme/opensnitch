package subscriptions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

func TestHandleRequestApplyThenList(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileStore(filepath.Join(root, "subscriptions.json"))
	if err != nil {
		t.Fatalf("creating file store: %v", err)
	}
	svc := NewService(store, WithRootDir(root))
	ctx := context.Background()

	applyReply, err := svc.HandleRequest(ctx, &protocol.SubscriptionRequest{
		Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_APPLY,
		Subscriptions: []*protocol.Subscription{{
			Name:            "hagezi-light",
			Url:             "https://example.invalid/hagezi.txt",
			Filename:        "hagezi-light.txt",
			Format:          "hosts",
			Enabled:         true,
			IntervalSeconds: 3600,
			TimeoutSeconds:  30,
			MaxBytes:        1024,
		}},
	})
	if err != nil {
		t.Fatalf("apply returned error: %v", err)
	}
	if !applyReply.Accepted {
		t.Fatalf("apply was not accepted: %+v", applyReply)
	}
	if len(applyReply.Subscriptions) != 1 {
		t.Fatalf("expected 1 stored subscription, got %d", len(applyReply.Subscriptions))
	}

	listReply, err := svc.HandleRequest(ctx, &protocol.SubscriptionRequest{
		Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_LIST,
	})
	if err != nil {
		t.Fatalf("list returned error: %v", err)
	}
	if len(listReply.Subscriptions) != 1 {
		t.Fatalf("expected 1 listed subscription, got %d", len(listReply.Subscriptions))
	}
	if listReply.Subscriptions[0].Status != protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_READY {
		t.Fatalf("expected ready status, got %s", listReply.Subscriptions[0].Status.String())
	}
}

func TestRefreshDownloadsAndCreatesRuleLinks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("0.0.0.0 example.com\n0.0.0.0 example.org\n"))
	}))
	defer server.Close()

	root := t.TempDir()
	store, err := NewFileStore(filepath.Join(root, "subscriptions.json"))
	if err != nil {
		t.Fatalf("creating file store: %v", err)
	}
	svc := NewService(store, WithRootDir(root))
	ctx := context.Background()

	applyReply, err := svc.HandleRequest(ctx, &protocol.SubscriptionRequest{
		Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_APPLY,
		Subscriptions: []*protocol.Subscription{{
			Name:            "hagezi-light",
			Url:             server.URL + "/hosts.txt",
			Filename:        "hagezi-light.txt",
			Format:          "hosts",
			Enabled:         true,
			Groups:          []string{"Ads", "Telemetry"},
			IntervalSeconds: 3600,
			TimeoutSeconds:  5,
			MaxBytes:        1024,
		}},
	})
	if err != nil || !applyReply.Accepted {
		t.Fatalf("apply failed: %v %+v", err, applyReply)
	}

	refreshReply, err := svc.HandleRequest(ctx, &protocol.SubscriptionRequest{
		Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_REFRESH,
		Force:     true,
		Subscriptions: []*protocol.Subscription{{
			Id: applyReply.Subscriptions[0].Id,
		}},
	})
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if !refreshReply.Accepted {
		t.Fatalf("refresh not accepted: %+v", refreshReply)
	}
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	listPath := filepath.Join(root, "sources.list.d", "hagezi-light-hosts.txt")
	if _, err := os.Stat(listPath); err != nil {
		t.Fatalf("expected downloaded list: %v", err)
	}
	allLink := filepath.Join(root, "rules.list.d", "all", "00-hagezi-light-hosts.txt")
	if _, err := os.Lstat(allLink); err != nil {
		t.Fatalf("expected all-group symlink: %v", err)
	}
	groupLink := filepath.Join(root, "rules.list.d", "ads", "00-hagezi-light-hosts.txt")
	if _, err := os.Lstat(groupLink); err != nil {
		t.Fatalf("expected group symlink: %v", err)
	}
	metaPath := listPath + ".meta.json"
	if _, err := os.Stat(metaPath); err != nil {
		t.Fatalf("expected metadata file: %v", err)
	}
}

func TestRestoreLayoutSymlinksPersistedDownloadedFiles(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "subscriptions.json")

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("creating file store: %v", err)
	}
	svc := NewService(store, WithRootDir(root))
	ctx := context.Background()

	applyReply, err := svc.HandleRequest(ctx, &protocol.SubscriptionRequest{
		Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_APPLY,
		Subscriptions: []*protocol.Subscription{{
			Name:            "persisted-list",
			Url:             "https://example.invalid/persisted.txt",
			Filename:        "persisted-list.txt",
			Format:          "hosts",
			Enabled:         true,
			Groups:          []string{"Ads"},
			IntervalSeconds: 3600,
			TimeoutSeconds:  5,
			MaxBytes:        1024,
		}},
	})
	if err != nil || !applyReply.Accepted {
		t.Fatalf("apply failed: %v %+v", err, applyReply)
	}

	listPath, _ := svc.pathsFor(applyReply.Subscriptions[0])
	if err := os.MkdirAll(filepath.Dir(listPath), 0755); err != nil {
		t.Fatalf("creating sources directory: %v", err)
	}
	if err := os.WriteFile(listPath, []byte("0.0.0.0 persisted.example\n"), 0600); err != nil {
		t.Fatalf("writing persisted downloaded list: %v", err)
	}
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	reloadedStore, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reloading store: %v", err)
	}
	reloadedSvc := NewService(reloadedStore, WithRootDir(root))
	if err := reloadedSvc.RestoreLayout(ctx); err != nil {
		t.Fatalf("restore layout failed: %v", err)
	}

	allLink := filepath.Join(root, "rules.list.d", "all", "00-persisted-list-hosts.txt")
	if _, err := os.Lstat(allLink); err != nil {
		t.Fatalf("expected all-group symlink: %v", err)
	}
	groupLink := filepath.Join(root, "rules.list.d", "ads", "00-persisted-list-hosts.txt")
	if _, err := os.Lstat(groupLink); err != nil {
		t.Fatalf("expected group symlink: %v", err)
	}
}
