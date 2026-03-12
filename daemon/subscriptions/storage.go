package subscriptions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

const (
	DefaultRootDir   = "/etc/opensnitchd/subscriptions"
	DefaultStoreFile = "/etc/opensnitchd/subscriptions/subscriptions.json"
)

type storageDocument struct {
	Version       int                      `json:"version"`
	Subscriptions []*protocol.Subscription `json:"subscriptions"`
}

type Storage struct {
	mu         sync.RWMutex
	path       string
	rootDir    string
	items      map[string]*protocol.Subscription
	meta       map[string]listMetadata
	dirtySubs  bool
	dirtyMeta  map[string]struct{}
	flushDelay time.Duration
	flushTimer *time.Timer
	flushErr   error
	closed     bool
}

type StorageOption func(*Storage)

func WithFlushDelay(delay time.Duration) StorageOption {
	return func(s *Storage) {
		if delay > 0 {
			s.flushDelay = delay
		}
	}
}

func NewStorage(path string, opts ...StorageOption) (*Storage, error) {
	if path == "" {
		path = DefaultStoreFile
	}

	s := &Storage{
		path:       path,
		rootDir:    filepath.Dir(path),
		items:      make(map[string]*protocol.Subscription),
		meta:       make(map[string]listMetadata),
		dirtyMeta:  make(map[string]struct{}),
		flushDelay: 800 * time.Millisecond,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if err := s.ensureStoreFile(); err != nil {
		return nil, err
	}
	if err := s.loadSubscriptionsFromDisk(); err != nil {
		return nil, err
	}
	if err := s.loadMetadataFromDisk(); err != nil {
		return nil, err
	}
	return s, nil
}

func NewFileStore(path string) (*Storage, error) {
	return NewStorage(path)
}

func NewMemoryStore() *Storage {
	return &Storage{
		items:      make(map[string]*protocol.Subscription),
		meta:       make(map[string]listMetadata),
		dirtyMeta:  make(map[string]struct{}),
		flushDelay: 800 * time.Millisecond,
	}
}

func (s *Storage) List(_ context.Context) ([]*protocol.Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.items))
	for key := range s.items {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	items := make([]*protocol.Subscription, 0, len(keys))
	for _, key := range keys {
		items = append(items, cloneSubscription(s.items[key]))
	}
	return items, nil
}

func (s *Storage) Apply(_ context.Context, items []*protocol.Subscription) ([]*protocol.Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	updated := make([]*protocol.Subscription, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		stored := cloneSubscription(item)
		stored.Id = subscriptionKey(stored)
		stored.Status = protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_READY
		stored.LastError = ""
		stored.LastUpdated = time.Now().UTC().Format(time.RFC3339)
		s.items[stored.Id] = stored
		updated = append(updated, cloneSubscription(stored))
	}

	s.dirtySubs = true
	s.scheduleFlushLocked()
	return updated, nil
}

func (s *Storage) Delete(_ context.Context, items []*protocol.Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, item := range items {
		if item == nil {
			continue
		}
		delete(s.items, subscriptionKey(item))
	}

	s.dirtySubs = true
	s.scheduleFlushLocked()
	return nil
}

func (s *Storage) Mark(_ context.Context, items []*protocol.Subscription, status protocol.SubscriptionStatus, lastError string) ([]*protocol.Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	updated := make([]*protocol.Subscription, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		key := subscriptionKey(item)
		stored, ok := s.items[key]
		if !ok {
			return nil, fmt.Errorf("subscription not found: %s", key)
		}
		stored.Status = status
		stored.LastError = lastError
		stored.LastUpdated = time.Now().UTC().Format(time.RFC3339)
		updated = append(updated, cloneSubscription(stored))
	}

	s.dirtySubs = true
	s.scheduleFlushLocked()
	return updated, nil
}

func (s *Storage) LoadMetadata(_ context.Context, metaPath string) (listMetadata, error) {
	s.mu.RLock()
	meta, ok := s.meta[metaPath]
	err := s.flushErr
	s.mu.RUnlock()
	if ok {
		if err != nil {
			return meta, err
		}
		return meta, nil
	}
	return defaultMetadata(), os.ErrNotExist
}

func (s *Storage) SaveMetadata(_ context.Context, metaPath string, meta listMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.meta[metaPath] = meta
	s.dirtyMeta[metaPath] = struct{}{}
	s.scheduleFlushLocked()
	return nil
}

func (s *Storage) Flush(_ context.Context) error {
	s.mu.Lock()
	if s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}
	return s.flushLocked()
}

func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}
	return s.flushLocked()
}

func (s *Storage) scheduleFlushLocked() {
	if s.path == "" {
		return
	}
	if s.flushDelay <= 0 {
		s.flushErr = s.flushLocked()
		return
	}
	if s.flushTimer != nil {
		s.flushTimer.Stop()
	}
	s.flushTimer = time.AfterFunc(s.flushDelay, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return
		}
		s.flushTimer = nil
		s.flushErr = s.flushLocked()
	})
}

func (s *Storage) flushLocked() error {
	if s.path == "" {
		s.dirtySubs = false
		s.dirtyMeta = make(map[string]struct{})
		return nil
	}

	if s.dirtySubs {
		if err := s.saveSubscriptionsLocked(); err != nil {
			return err
		}
		s.dirtySubs = false
	}
	for metaPath := range s.dirtyMeta {
		meta := s.meta[metaPath]
		if err := saveMetadataFile(metaPath, meta); err != nil {
			return err
		}
		delete(s.dirtyMeta, metaPath)
	}
	return nil
}

func (s *Storage) ensureStoreFile() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating subscriptions directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return fmt.Errorf("setting subscriptions directory permissions %s: %w", dir, err)
	}

	if _, err := os.Stat(s.path); err == nil {
		return os.Chmod(s.path, 0600)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking store file %s: %w", s.path, err)
	}

	return writeAtomic0600(s.path, []byte(`{"version":1,"subscriptions":[]}`))
}

func (s *Storage) loadSubscriptionsFromDisk() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("reading subscriptions store %s: %w", s.path, err)
	}

	var doc storageDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parsing subscriptions store %s: %w", s.path, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = make(map[string]*protocol.Subscription)
	for _, item := range doc.Subscriptions {
		if item == nil {
			continue
		}
		normalized := normalizeSubscription(item)
		s.items[normalized.Id] = normalized
	}
	return nil
}

func (s *Storage) saveSubscriptionsLocked() error {
	doc := storageDocument{Version: 1, Subscriptions: make([]*protocol.Subscription, 0, len(s.items))}
	keys := make([]string, 0, len(s.items))
	for key := range s.items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		doc.Subscriptions = append(doc.Subscriptions, cloneSubscription(s.items[key]))
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling subscriptions store: %w", err)
	}
	if err := writeAtomic0600(s.path, raw); err != nil {
		return fmt.Errorf("writing subscriptions store %s: %w", s.path, err)
	}
	return nil
}

func (s *Storage) loadMetadataFromDisk() error {
	if s.rootDir == "" {
		return nil
	}
	sourcesDir := filepath.Join(s.rootDir, "sources.list.d")
	entries, err := os.ReadDir(sourcesDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".meta.json") {
			continue
		}
		metaPath := filepath.Join(sourcesDir, entry.Name())
		raw, readErr := os.ReadFile(metaPath)
		if readErr != nil {
			continue
		}
		meta := defaultMetadata()
		if unmarshalErr := json.Unmarshal(raw, &meta); unmarshalErr != nil {
			continue
		}
		if meta.Version == 0 {
			meta.Version = 1
		}
		if meta.Format == "" {
			meta.Format = defaultFormat
		}
		if meta.LastResult == "" {
			meta.LastResult = "never"
		}
		s.meta[metaPath] = meta
	}
	return nil
}

func saveMetadataFile(metaPath string, meta listMetadata) error {
	if err := os.MkdirAll(filepath.Dir(metaPath), 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic0600(metaPath, raw)
}

func subscriptionKey(item *protocol.Subscription) string {
	if item == nil {
		return ""
	}
	if item.Id != "" {
		return item.Id
	}
	return fmt.Sprintf("%s|%s|%s|%s", item.Node, item.Name, item.Filename, item.Url)
}

func cloneSubscription(item *protocol.Subscription) *protocol.Subscription {
	if item == nil {
		return nil
	}
	clone := &protocol.Subscription{
		Id:              item.Id,
		Name:            item.Name,
		Url:             item.Url,
		Filename:        item.Filename,
		Enabled:         item.Enabled,
		Format:          item.Format,
		IntervalSeconds: item.IntervalSeconds,
		TimeoutSeconds:  item.TimeoutSeconds,
		MaxBytes:        item.MaxBytes,
		Node:            item.Node,
		Status:          item.Status,
		LastUpdated:     item.LastUpdated,
		LastError:       item.LastError,
	}
	if item.Groups != nil {
		clone.Groups = append([]string(nil), item.Groups...)
	}
	return clone
}

func writeAtomic0600(path string, raw []byte) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".subscriptions-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(raw); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
