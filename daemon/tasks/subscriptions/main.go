package subscriptions

import (
	"context"
	"fmt"
	"sync"
	"time"

	subsvc "github.com/evilsocket/opensnitch/daemon/subscriptions"
	"github.com/evilsocket/opensnitch/daemon/tasks/base"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

var Name = "subscriptions"

type Task struct {
	base.TaskBase

	mu      *sync.RWMutex
	service *subsvc.Service
	request *protocol.SubscriptionRequest
}

func New(service *subsvc.Service, request *protocol.SubscriptionRequest, stopOnDisconnect bool) (string, *Task) {
	name := fmt.Sprintf("%s-%s-%d", Name, request.Operation.String(), time.Now().UnixNano())
	return name, &Task{
		TaskBase: base.TaskBase{
			Name:             Name,
			Results:          make(chan interface{}, 1),
			Errors:           make(chan error, 1),
			StopOnDisconnect: stopOnDisconnect,
		},
		mu:      &sync.RWMutex{},
		service: service,
		request: request,
	}
}

func (t *Task) Start(ctx context.Context, cancel context.CancelFunc) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.Ctx = ctx
	t.Cancel = cancel
	if t.service == nil {
		return fmt.Errorf("subscription service is nil")
	}
	if t.request == nil {
		return fmt.Errorf("subscription request is nil")
	}

	go func() {
		defer cancel()

		var (
			reply *protocol.SubscriptionReply
			err   error
		)

		switch t.request.Operation {
		case protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_REFRESH:
			reply, err = t.service.Refresh(ctx, t.request)
		case protocol.SubscriptionOperation_SUBSCRIPTION_OPERATION_DEPLOY:
			reply, err = t.service.Deploy(ctx, t.request)
		default:
			err = fmt.Errorf("unsupported task operation: %s", t.request.Operation.String())
		}

		if err != nil {
			t.TaskBase.Errors <- err
			return
		}

		select {
		case <-ctx.Done():
			return
		case t.TaskBase.Results <- reply:
		}
	}()

	return nil
}

func (t *Task) Pause() error {
	return nil
}

func (t *Task) Resume() error {
	return nil
}

func (t *Task) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Cancel != nil {
		t.Cancel()
	}
	return nil
}

func (t *Task) Results() <-chan interface{} {
	return t.TaskBase.Results
}

func (t *Task) Errors() <-chan error {
	return t.TaskBase.Errors
}
