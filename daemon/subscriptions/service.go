package subscriptions

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

type Store interface {
	List(context.Context) ([]*protocol.Subscription, error)
	Apply(context.Context, []*protocol.Subscription) ([]*protocol.Subscription, error)
	Delete(context.Context, []*protocol.Subscription) error
	Mark(context.Context, []*protocol.Subscription, protocol.SubscriptionStatus, string) ([]*protocol.Subscription, error)
	LoadMetadata(context.Context, string) (listMetadata, error)
	SaveMetadata(context.Context, string, listMetadata) error
	Flush(context.Context) error
}

type Service struct {
	store     Store
	rootDir   string
	userAgent string
}

type Option func(*Service)

func WithRootDir(rootDir string) Option {
	return func(s *Service) {
		if rootDir != "" {
			s.rootDir = rootDir
		}
	}
}

func WithUserAgent(userAgent string) Option {
	return func(s *Service) {
		if userAgent != "" {
			s.userAgent = userAgent
		}
	}
}

func NewService(store Store, opts ...Option) *Service {
	s := &Service{
		store:     store,
		rootDir:   DefaultRootDir,
		userAgent: defaultUserAgent,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

func (s *Service) HandleRequest(ctx context.Context, req *protocol.SubscriptionRequest) (*protocol.SubscriptionReply, error) {
	if req == nil {
		return &protocol.SubscriptionReply{Message: "missing request"}, fmt.Errorf("missing request")
	}

	switch req.Operation {
	case protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_LIST:
		return s.list(ctx)
	case protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_APPLY:
		return s.apply(ctx, req.Subscriptions)
	case protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_DELETE:
		return s.delete(ctx, req.Subscriptions)
	case protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_REFRESH:
		return s.Refresh(ctx, req)
	case protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_DEPLOY:
		return s.Deploy(ctx, req)
	default:
		return &protocol.SubscriptionReply{
			Operation: req.Operation,
			Message:   "unsupported operation",
			Accepted:  false,
		}, fmt.Errorf("unsupported operation: %s", req.Operation.String())
	}
}

// StatusCounts returns a minimal aggregate view of subscription health.
func (s *Service) StatusCounts(ctx context.Context) (total, ready, errored uint64, err error) {
	items, err := s.store.List(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	for _, item := range items {
		if item == nil {
			continue
		}
		total++
		switch item.Status {
		case protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_READY:
			ready++
		case protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_ERROR:
			errored++
		}
	}

	return total, ready, errored, nil
}

func (s *Service) Refresh(ctx context.Context, req *protocol.SubscriptionRequest) (*protocol.SubscriptionReply, error) {
	items, err := s.selectSubscriptions(ctx, req)
	if err != nil {
		return &protocol.SubscriptionReply{
			Operation: req.Operation,
			Message:   "failed to resolve subscriptions for refresh",
			Accepted:  false,
		}, err
	}
	if len(items) == 0 {
		return &protocol.SubscriptionReply{
			Operation: req.Operation,
			Message:   "no subscriptions selected",
			Accepted:  true,
		}, nil
	}

	_, _ = s.store.Mark(ctx, items, protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_SYNCING, "")

	var errors []string
	for _, item := range items {
		state, refreshErr := s.refreshOne(ctx, item, req.Force)
		if refreshErr != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", item.Name, refreshErr))
			_, _ = s.store.Mark(ctx, []*protocol.Subscription{item}, protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_ERROR, refreshErr.Error())
			continue
		}
		if state == refreshStateSyncing {
			state = refreshStateReady
		}
		_, _ = s.store.Mark(ctx, []*protocol.Subscription{item}, protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_READY, "")
	}

	if syncErr := s.syncLayout(ctx); syncErr != nil {
		errors = append(errors, syncErr.Error())
	}

	updated, err := s.selectedSnapshot(ctx, items)
	if err != nil {
		return &protocol.SubscriptionReply{
			Operation: req.Operation,
			Message:   "failed to load refreshed subscriptions",
			Accepted:  false,
		}, err
	}

	return &protocol.SubscriptionReply{
		Operation:     req.Operation,
		Subscriptions: updated,
		Errors:        errors,
		Message:       s.refreshMessage("refresh", updated, len(errors)),
		Accepted:      len(errors) == 0,
	}, nil
}

func (s *Service) Deploy(ctx context.Context, req *protocol.SubscriptionRequest) (*protocol.SubscriptionReply, error) {
	items, err := s.selectSubscriptions(ctx, req)
	if err != nil {
		return &protocol.SubscriptionReply{
			Operation: req.Operation,
			Message:   "failed to resolve subscriptions for deploy",
			Accepted:  false,
		}, err
	}
	targets := "local node"
	if len(req.Targets) > 0 {
		targets = strings.Join(req.Targets, ",")
	}
	if err := s.syncLayout(ctx); err != nil {
		return &protocol.SubscriptionReply{
			Operation: req.Operation,
			Message:   "failed to deploy subscription layout",
			Accepted:  false,
		}, err
	}
	updated, err := s.selectedSnapshot(ctx, items)
	if err != nil {
		return &protocol.SubscriptionReply{
			Operation: req.Operation,
			Message:   "failed to load deployed subscriptions",
			Accepted:  false,
		}, err
	}

	return &protocol.SubscriptionReply{
		Operation:     req.Operation,
		Subscriptions: updated,
		Message:       fmt.Sprintf("subscription layout deployed for %s", targets),
		Accepted:      true,
	}, nil
}

func (s *Service) list(ctx context.Context) (*protocol.SubscriptionReply, error) {
	items, err := s.store.List(ctx)
	if err != nil {
		return &protocol.SubscriptionReply{
			Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_LIST,
			Message:   "failed to list subscriptions",
			Accepted:  false,
		}, err
	}

	return &protocol.SubscriptionReply{
		Operation:     protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_LIST,
		Subscriptions: items,
		Message:       "subscriptions loaded",
		Accepted:      true,
	}, nil
}

func (s *Service) apply(ctx context.Context, items []*protocol.Subscription) (*protocol.SubscriptionReply, error) {
	if len(items) == 0 {
		return &protocol.SubscriptionReply{
			Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_APPLY,
			Message:   "no subscriptions supplied",
			Accepted:  false,
		}, fmt.Errorf("no subscriptions supplied")
	}

	normalized := make([]*protocol.Subscription, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		normalized = append(normalized, normalizeSubscription(item))
	}
	if len(normalized) == 0 {
		return &protocol.SubscriptionReply{
			Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_APPLY,
			Message:   "no valid subscriptions supplied",
			Accepted:  false,
		}, fmt.Errorf("no valid subscriptions supplied")
	}

	updated, err := s.store.Apply(ctx, normalized)
	if err != nil {
		return &protocol.SubscriptionReply{
			Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_APPLY,
			Message:   "failed to store subscriptions",
			Accepted:  false,
		}, err
	}

	return &protocol.SubscriptionReply{
		Operation:     protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_APPLY,
		Subscriptions: updated,
		Message:       "subscriptions stored",
		Accepted:      true,
	}, s.syncLayout(ctx)
}

func (s *Service) delete(ctx context.Context, items []*protocol.Subscription) (*protocol.SubscriptionReply, error) {
	if len(items) == 0 {
		return &protocol.SubscriptionReply{
			Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_DELETE,
			Message:   "no subscriptions supplied",
			Accepted:  false,
		}, fmt.Errorf("no subscriptions supplied")
	}

	if err := s.store.Delete(ctx, items); err != nil {
		return &protocol.SubscriptionReply{
			Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_DELETE,
			Message:   "failed to delete subscriptions",
			Accepted:  false,
		}, err
	}

	return &protocol.SubscriptionReply{
		Operation: protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_DELETE,
		Message:   "subscriptions deleted",
		Accepted:  true,
	}, s.syncLayout(ctx)
}

func normalizeSubscription(item *protocol.Subscription) *protocol.Subscription {
	clone := cloneSubscription(item)
	if clone.Id == "" {
		clone.Id = subscriptionKey(clone)
	}
	if clone.Format == "" {
		clone.Format = "hosts"
	}
	clone.Format = normalizeFormat(clone.Format)
	if clone.Filename == "" {
		clone.Filename = ensureFilename(clone.Name, clone.Url, clone.Filename, clone.Format)
	}
	if clone.Name == "" {
		clone.Name = clone.Filename
	}
	clone.Groups = normalizeGroups(clone.Groups)
	if clone.IntervalSeconds == 0 {
		clone.IntervalSeconds = defaultIntervalSeconds
	}
	if clone.TimeoutSeconds == 0 {
		clone.TimeoutSeconds = defaultTimeoutSeconds
	}
	if clone.MaxBytes == 0 {
		clone.MaxBytes = defaultMaxBytes
	}
	if clone.Status == protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_UNSPECIFIED {
		clone.Status = protocol.SubscriptionStatus_SUBSCRIPTION_STATUS_PENDING
	}
	if clone.LastUpdated == "" {
		clone.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	}
	return clone
}

func (s *Service) refreshMessage(action string, items []*protocol.Subscription, errorCount int) string {
	if len(items) == 0 {
		return fmt.Sprintf("no subscriptions %sed", action)
	}
	if errorCount == 0 {
		return fmt.Sprintf("%d subscriptions %sed", len(items), action)
	}
	return fmt.Sprintf("%d subscriptions %sed, %d failed", len(items), action, errorCount)
}

func (s *Service) Flush(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Flush(ctx)
}

func (s *Service) RestoreLayout(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.syncLayout(ctx)
}
