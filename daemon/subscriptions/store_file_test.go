package subscriptions

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

func TestFileStorePersistsApplyAndReload(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	storePath := filepath.Join(root, "subscriptions.json")

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("creating file store: %v", err)
	}

	_, err = store.Apply(ctx, []*protocol.Subscription{{
		Name:     "test-sub",
		Url:      "https://example.invalid/list.txt",
		Filename: "list.txt",
		Format:   "hosts",
		Enabled:  true,
	}})
	if err != nil {
		t.Fatalf("applying subscription: %v", err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatalf("flushing storage: %v", err)
	}

	reloaded, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reloading file store: %v", err)
	}

	items, err := reloaded.List(ctx)
	if err != nil {
		t.Fatalf("listing subscriptions: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 subscription after reload, got %d", len(items))
	}
	if items[0].Name != "test-sub" {
		t.Fatalf("unexpected subscription name: %s", items[0].Name)
	}
}

func TestFileStorePermissions0600(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "subscriptions.json")

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("creating file store: %v", err)
	}

	_, err = store.Apply(context.Background(), []*protocol.Subscription{{
		Name:     "perm-check",
		Url:      "https://example.invalid/perm.txt",
		Filename: "perm.txt",
		Format:   "hosts",
		Enabled:  true,
	}})
	if err != nil {
		t.Fatalf("applying subscription: %v", err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatalf("flushing storage: %v", err)
	}

	st, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("stat store file: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected mode 0600, got %o", st.Mode().Perm())
	}

	dirSt, err := os.Stat(filepath.Dir(storePath))
	if err != nil {
		t.Fatalf("stat store dir: %v", err)
	}
	if dirSt.Mode().Perm() != 0755 {
		t.Fatalf("expected dir mode 0755, got %o", dirSt.Mode().Perm())
	}
}

func TestFileStoreFixesExistingDirectoryPermissions(t *testing.T) {
	root := t.TempDir()
	storeDir := filepath.Join(root, "subs")
	storePath := filepath.Join(storeDir, "subscriptions.json")

	if err := os.MkdirAll(storeDir, 0755); err != nil {
		t.Fatalf("creating pre-existing dir: %v", err)
	}
	if err := os.Chmod(storeDir, 0755); err != nil {
		t.Fatalf("chmod pre-existing dir: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("creating file store: %v", err)
	}

	dirSt, err := os.Stat(storeDir)
	if err != nil {
		t.Fatalf("stat store dir: %v", err)
	}
	if dirSt.Mode().Perm() != 0755 {
		t.Fatalf("expected dir mode 0755, got %o", dirSt.Mode().Perm())
	}
}
