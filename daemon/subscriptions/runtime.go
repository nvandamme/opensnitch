package subscriptions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

const (
	defaultFormat          = "hosts"
	defaultIntervalSeconds = 24 * 3600
	defaultTimeoutSeconds  = 60
	defaultMaxBytes        = 20 * 1024 * 1024
	defaultUserAgent       = "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"

	refreshStateReady       = "ready"
	refreshStateSyncing     = "syncing"
	refreshStateUpdated     = "updated"
	refreshStateNotModified = "not_modified"
	refreshStateBusy        = "busy"
	refreshStateNotDue      = "not_due"
	refreshStateBackoff     = "backoff"
)

type fileLock struct {
	path string
	held bool
}

func newFileLock(path string) *fileLock {
	return &fileLock{path: path}
}

func (l *fileLock) acquire() bool {
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return false
	}
	file.Close()
	l.held = true
	return true
}

func (l *fileLock) release() {
	if !l.held {
		return
	}
	_ = os.Remove(l.path)
	l.held = false
}

func (s *Service) selectSubscriptions(ctx context.Context, req *protocol.SubscriptionRequest) ([]*protocol.Subscription, error) {
	items, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || (len(req.Subscriptions) == 0 && len(req.Targets) == 0) {
		return items, nil
	}

	selected := make([]*protocol.Subscription, 0, len(items))
	seen := make(map[string]struct{})
	for _, item := range items {
		if item == nil {
			continue
		}
		if matchesSelection(item, req) {
			if _, ok := seen[item.Id]; ok {
				continue
			}
			seen[item.Id] = struct{}{}
			selected = append(selected, item)
		}
	}
	return selected, nil
}

func matchesSelection(item *protocol.Subscription, req *protocol.SubscriptionRequest) bool {
	for _, candidate := range req.Subscriptions {
		if candidate == nil {
			continue
		}
		if sameSubscription(item, candidate) {
			return true
		}
	}
	for _, target := range req.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if target == item.Id || target == item.Name || target == item.Filename || target == item.Url {
			return true
		}
	}
	return false
}

func sameSubscription(left, right *protocol.Subscription) bool {
	if left == nil || right == nil {
		return false
	}
	if left.Id != "" && right.Id != "" {
		return left.Id == right.Id
	}
	return subscriptionKey(left) == subscriptionKey(right)
}

func (s *Service) selectedSnapshot(ctx context.Context, selected []*protocol.Subscription) ([]*protocol.Subscription, error) {
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		return all, nil
	}

	keys := make(map[string]struct{}, len(selected))
	for _, item := range selected {
		if item != nil {
			keys[subscriptionKey(item)] = struct{}{}
		}
	}

	out := make([]*protocol.Subscription, 0, len(selected))
	for _, item := range all {
		if item == nil {
			continue
		}
		if _, ok := keys[subscriptionKey(item)]; ok {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *Service) syncLayout(ctx context.Context) error {
	items, err := s.store.List(ctx)
	if err != nil {
		return err
	}
	if err := s.ensureLayout(); err != nil {
		return err
	}
	if err := s.syncSources(items); err != nil {
		return err
	}
	return s.syncRuleLinks(items)
}

func (s *Service) ensureLayout() error {
	paths := []string{
		s.rootDir,
		filepath.Join(s.rootDir, "sources.list.d"),
		filepath.Join(s.rootDir, "rules.list.d"),
	}
	for _, dir := range paths {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) syncSources(items []*protocol.Subscription) error {
	sourcesDir := filepath.Join(s.rootDir, "sources.list.d")
	desired := make(map[string]struct{}, len(items)*2)
	for _, item := range items {
		if item == nil {
			continue
		}
		listPath, metaPath := s.pathsFor(item)
		desired[listPath] = struct{}{}
		desired[metaPath] = struct{}{}
	}
	entries, err := os.ReadDir(sourcesDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		fullPath := filepath.Join(sourcesDir, entry.Name())
		if _, ok := desired[fullPath]; ok {
			continue
		}
		if removeErr := os.Remove(fullPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
	}
	return nil
}

func (s *Service) syncRuleLinks(items []*protocol.Subscription) error {
	rulesRoot := filepath.Join(s.rootDir, "rules.list.d")
	type itemWithPath struct {
		subscription *protocol.Subscription
		listPath     string
	}
	filtered := make([]itemWithPath, 0, len(items))
	for _, item := range items {
		if item == nil || !item.Enabled {
			continue
		}
		listPath, _ := s.pathsFor(item)
		if _, err := os.Stat(listPath); err != nil {
			continue
		}
		filtered = append(filtered, itemWithPath{subscription: item, listPath: listPath})
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].subscription.Id < filtered[j].subscription.Id
	})

	desired := make(map[string]map[string]string)
	for idx, item := range filtered {
		linkName := fmt.Sprintf("%02d-%s", idx, filepath.Base(item.listPath))
		groups := append([]string{subscriptionDirName(item.subscription), "all"}, normalizeGroups(item.subscription.Groups)...)
		for _, group := range groups {
			if _, ok := desired[group]; !ok {
				desired[group] = make(map[string]string)
			}
			desired[group][linkName] = item.listPath
		}
	}

	entries, err := os.ReadDir(rulesRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		groupPath := filepath.Join(rulesRoot, entry.Name())
		if _, ok := desired[entry.Name()]; !ok {
			if removeErr := os.RemoveAll(groupPath); removeErr != nil {
				return removeErr
			}
		}
	}

	for group, links := range desired {
		groupPath := filepath.Join(rulesRoot, group)
		if err := os.MkdirAll(groupPath, 0755); err != nil {
			return err
		}
		if err := os.Chmod(groupPath, 0755); err != nil {
			return err
		}
		existing, err := os.ReadDir(groupPath)
		if err != nil {
			return err
		}
		for _, entry := range existing {
			linkPath := filepath.Join(groupPath, entry.Name())
			target, ok := links[entry.Name()]
			if !ok {
				if removeErr := os.RemoveAll(linkPath); removeErr != nil {
					return removeErr
				}
				continue
			}
			currentTarget, readErr := os.Readlink(linkPath)
			if readErr == nil && currentTarget == target {
				continue
			}
			if removeErr := os.RemoveAll(linkPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return removeErr
			}
		}
		for name, target := range links {
			linkPath := filepath.Join(groupPath, name)
			if _, err := os.Lstat(linkPath); err == nil {
				continue
			}
			if err := os.Symlink(target, linkPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Service) refreshOne(ctx context.Context, sub *protocol.Subscription, force bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return refreshStateSyncing, err
	}
	if err := s.ensureLayout(); err != nil {
		return refreshStateSyncing, err
	}

	listPath, metaPath := s.pathsFor(sub)
	meta, err := s.store.LoadMetadata(ctx, metaPath)
	if err != nil {
		meta = defaultMetadata()
	}
	meta.Version = 1
	meta.URL = sub.Url
	meta.Format = normalizeFormat(sub.Format)
	meta.LastChecked = time.Now().UTC().Format(time.RFC3339)
	meta.LastError = ""

	if !force {
		if inBackoff(meta) {
			if saveErr := s.store.SaveMetadata(ctx, metaPath, meta); saveErr != nil {
				return refreshStateBackoff, saveErr
			}
			return refreshStateBackoff, nil
		}
		if !isDue(meta, sub.IntervalSeconds) {
			if saveErr := s.store.SaveMetadata(ctx, metaPath, meta); saveErr != nil {
				return refreshStateNotDue, saveErr
			}
			return refreshStateNotDue, nil
		}
	}

	lock := newFileLock(listPath + ".lock")
	if !lock.acquire() {
		meta.LastResult = refreshStateBusy
		if saveErr := s.store.SaveMetadata(ctx, metaPath, meta); saveErr != nil {
			return refreshStateBusy, saveErr
		}
		return refreshStateBusy, errors.New("subscription is busy")
	}
	defer lock.release()

	headers := make(http.Header)
	if !force && meta.ETag != "" {
		headers.Set("If-None-Match", meta.ETag)
	}
	if !force && meta.LastModified != "" {
		headers.Set("If-Modified-Since", meta.LastModified)
	}
	headers.Set("User-Agent", s.userAgent)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.Url, nil)
	if err != nil {
		markFailure(&meta, err.Error())
		_ = s.store.SaveMetadata(ctx, metaPath, meta)
		return refreshStateSyncing, err
	}
	req.Header = headers

	client := &http.Client{Timeout: time.Duration(sub.TimeoutSeconds) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		markFailure(&meta, err.Error())
		_ = s.store.SaveMetadata(ctx, metaPath, meta)
		return refreshStateSyncing, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		meta.FailCount = 0
		meta.BackoffUntil = ""
		meta.LastResult = refreshStateNotModified
		if err := s.store.SaveMetadata(ctx, metaPath, meta); err != nil {
			return refreshStateNotModified, err
		}
		return refreshStateNotModified, nil
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("http_%d", resp.StatusCode)
		markFailure(&meta, err.Error())
		_ = s.store.SaveMetadata(ctx, metaPath, meta)
		return refreshStateSyncing, err
	}

	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		var declared int64
		if _, scanErr := fmt.Sscan(contentLength, &declared); scanErr == nil && declared > int64(sub.MaxBytes) {
			err = fmt.Errorf("too_large:%s", contentLength)
			markFailure(&meta, err.Error())
			_ = s.store.SaveMetadata(ctx, metaPath, meta)
			return refreshStateSyncing, err
		}
	}

	if err := os.MkdirAll(filepath.Dir(listPath), 0755); err != nil {
		return refreshStateSyncing, err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(listPath), ".subscription-*.tmp")
	if err != nil {
		return refreshStateSyncing, err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return refreshStateSyncing, err
	}

	var downloaded int64
	sampleLines := make([]string, 0, 200)
	leftover := ""
	buffer := make([]byte, 32*1024)
	for {
		readBytes, readErr := resp.Body.Read(buffer)
		if readBytes > 0 {
			chunk := buffer[:readBytes]
			downloaded += int64(readBytes)
			if downloaded > int64(sub.MaxBytes) {
				tmpFile.Close()
				err = errors.New("too_large_streamed")
				markFailure(&meta, err.Error())
				_ = s.store.SaveMetadata(ctx, metaPath, meta)
				return refreshStateSyncing, err
			}
			if _, err := tmpFile.Write(chunk); err != nil {
				tmpFile.Close()
				markFailure(&meta, err.Error())
				_ = s.store.SaveMetadata(ctx, metaPath, meta)
				return refreshStateSyncing, err
			}
			if normalizeFormat(sub.Format) == defaultFormat && len(sampleLines) < 200 {
				leftover = collectSampleLines(leftover+string(chunk), &sampleLines)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			tmpFile.Close()
			markFailure(&meta, readErr.Error())
			_ = s.store.SaveMetadata(ctx, metaPath, meta)
			return refreshStateSyncing, readErr
		}
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return refreshStateSyncing, err
	}
	if err := tmpFile.Close(); err != nil {
		return refreshStateSyncing, err
	}

	if normalizeFormat(sub.Format) == defaultFormat && !isHostsFileLike(sampleLines) {
		err = errors.New("bad_format_hosts")
		markFailure(&meta, err.Error())
		_ = s.store.SaveMetadata(ctx, metaPath, meta)
		return refreshStateSyncing, err
	}

	if err := os.Rename(tmpPath, listPath); err != nil {
		markFailure(&meta, err.Error())
		_ = s.store.SaveMetadata(ctx, metaPath, meta)
		return refreshStateSyncing, err
	}
	if err := os.Chmod(listPath, 0600); err != nil {
		return refreshStateSyncing, err
	}
	fsyncParentDir(listPath)

	if etag := resp.Header.Get("ETag"); etag != "" {
		meta.ETag = etag
	}
	if lastModified := resp.Header.Get("Last-Modified"); lastModified != "" {
		meta.LastModified = lastModified
	}
	meta.Bytes = downloaded
	meta.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	meta.FailCount = 0
	meta.BackoffUntil = ""
	meta.LastResult = refreshStateUpdated
	meta.LastError = ""
	if err := s.store.SaveMetadata(ctx, metaPath, meta); err != nil {
		return refreshStateUpdated, err
	}

	return refreshStateUpdated, nil
}

func (s *Service) pathsFor(sub *protocol.Subscription) (string, string) {
	filename := ensureFilename(sub.Name, sub.Url, sub.Filename, sub.Format)
	listPath := filepath.Join(s.rootDir, "sources.list.d", filename)
	return listPath, listPath + ".meta.json"
}

func inBackoff(meta listMetadata) bool {
	if meta.BackoffUntil == "" {
		return false
	}
	until, err := time.Parse(time.RFC3339, meta.BackoffUntil)
	if err != nil {
		return false
	}
	return time.Now().UTC().Before(until)
}

func isDue(meta listMetadata, intervalSeconds uint32) bool {
	if meta.LastChecked == "" {
		return true
	}
	lastChecked, err := time.Parse(time.RFC3339, meta.LastChecked)
	if err != nil {
		return true
	}
	return time.Since(lastChecked) >= time.Duration(intervalSeconds)*time.Second
}

func markFailure(meta *listMetadata, reason string) {
	meta.FailCount++
	meta.LastError = reason
	meta.LastResult = "error"
	seconds := time.Duration(1<<max(0, meta.FailCount)) * time.Minute
	if seconds > 6*time.Hour {
		seconds = 6 * time.Hour
	}
	meta.BackoffUntil = time.Now().UTC().Add(seconds).Format(time.RFC3339)
}

func normalizeFormat(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return defaultFormat
	}
	return value
}

func ensureFilename(name, rawURL, filename, format string) string {
	filename = safeName(filename)
	if filename == "" {
		if parsedURL, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
			filename = safeName(path.Base(parsedURL.Path))
		}
	}
	if filename == "" {
		filename = slugName(name)
	}
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	format = normalizeFormat(format)
	suffix := "-" + format
	if !strings.HasSuffix(strings.ToLower(base), suffix) {
		base += suffix
	}
	ext := filepath.Ext(filename)
	if ext == "" {
		ext = ".txt"
	}
	return safeName(base + ext)
}

func subscriptionDirName(sub *protocol.Subscription) string {
	filename := ensureFilename(sub.Name, sub.Url, sub.Filename, sub.Format)
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	format := normalizeFormat(sub.Format)
	suffix := "-" + format
	if !strings.HasSuffix(strings.ToLower(base), suffix) {
		base += suffix
	}
	return safeName(base)
}

func normalizeGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		normalized := normalizeGroup(group)
		if normalized == "" || normalized == "all" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeGroup(group string) string {
	group = strings.TrimSpace(strings.ToLower(group))
	if group == "" {
		return ""
	}
	var builder strings.Builder
	for _, char := range group {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		case char == '.' || char == '_' || char == '-':
			builder.WriteRune(char)
		default:
			builder.WriteRune('-')
		}
	}
	return strings.Trim(builder.String(), "-._")
}

func safeName(value string) string {
	value = filepath.Base(strings.TrimSpace(value))
	if value == "." || value == string(filepath.Separator) {
		return ""
	}
	return value
}

func slugName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "subscription.list"
	}
	var builder strings.Builder
	lastDash := false
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
			lastDash = false
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
			lastDash = false
		case char == '.' || char == '_' || char == '-':
			builder.WriteRune(char)
			lastDash = false
		default:
			if !lastDash {
				builder.WriteRune('-')
				lastDash = true
			}
		}
	}
	name := strings.Trim(builder.String(), "-._")
	if name == "" {
		name = "subscription"
	}
	if !strings.Contains(name, ".") {
		name += ".list"
	}
	return safeName(name)
}

func collectSampleLines(chunk string, sampleLines *[]string) string {
	parts := strings.Split(chunk, "\n")
	limit := len(parts) - 1
	if !strings.HasSuffix(chunk, "\n") {
		limit = len(parts) - 1
	}
	for idx := 0; idx < limit && len(*sampleLines) < 200; idx++ {
		*sampleLines = append(*sampleLines, strings.TrimSuffix(parts[idx], "\r"))
	}
	if strings.HasSuffix(chunk, "\n") {
		return ""
	}
	return parts[len(parts)-1]
}

func isHostsFileLike(sampleLines []string) bool {
	valid := 0
	total := 0
	for _, line := range sampleLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		total++
		parts := strings.Fields(trimmed)
		switch {
		case len(parts) >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" || parts[0] == "::"):
			if strings.Contains(parts[1], ".") && !strings.Contains(parts[1], "/") {
				valid++
			}
		case len(parts) == 1 && strings.Contains(parts[0], "."):
			valid++
		}
	}
	if total <= 10 {
		return true
	}
	return float64(valid)/float64(total) >= 0.60
}

func fsyncParentDir(path string) {
	parent := filepath.Dir(path)
	if parent == "" {
		return
	}
	file, err := os.Open(parent)
	if err != nil {
		return
	}
	defer file.Close()
	_ = file.Sync()
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
