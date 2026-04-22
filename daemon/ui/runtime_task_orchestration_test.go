package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/tasks"
	taskBase "github.com/evilsocket/opensnitch/daemon/tasks/base"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"google.golang.org/grpc/metadata"
)

type notificationsMockStream struct {
	replies []*protocol.NotificationReply
}

func (m *notificationsMockStream) Send(reply *protocol.NotificationReply) error {
	m.replies = append(m.replies, reply)
	return nil
}

func (m *notificationsMockStream) Recv() (*protocol.Notification, error) {
	return nil, io.EOF
}

func (m *notificationsMockStream) Header() (metadata.MD, error) {
	return metadata.MD{}, nil
}

func (m *notificationsMockStream) Trailer() metadata.MD {
	return metadata.MD{}
}

func (m *notificationsMockStream) CloseSend() error {
	return nil
}

func (m *notificationsMockStream) Context() context.Context {
	return context.Background()
}

func (m *notificationsMockStream) SendMsg(_ interface{}) error {
	return nil
}

func (m *notificationsMockStream) RecvMsg(_ interface{}) error {
	return io.EOF
}

func drainTaskEvents(ctx context.Context, tm *tasks.TaskManager) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tm.TaskAdded:
			case <-tm.TaskRemoved:
			}
		}
	}()
}

func taskNotificationJSON(t *testing.T, name string, data interface{}) string {
	t.Helper()
	payload, err := json.Marshal(taskBase.TaskNotification{Name: name, Data: data})
	if err != nil {
		t.Fatalf("marshal task notification: %v", err)
	}
	return string(payload)
}

func newRuntimeTaskParityFixture(t *testing.T) (*Client, *notificationsMockStream) {
	t.Helper()

	TaskMgr = tasks.NewTaskManager()
	t.Cleanup(func() {
		TaskMgr.Stop()
	})
	drainTaskEvents(TaskMgr.Ctx, TaskMgr)

	return &Client{}, &notificationsMockStream{}
}

func assertNoReplyWithin(t *testing.T, stream *notificationsMockStream, start int, wait time.Duration, msg string) {
	t.Helper()

	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if got := len(stream.replies) - start; got != 0 {
			t.Fatalf("%s, got %d", msg, got)
		}
		time.Sleep(5 * time.Millisecond)
	}

	if got := len(stream.replies) - start; got != 0 {
		t.Fatalf("%s, got %d", msg, got)
	}
}

func waitForReplyWithin(t *testing.T, stream *notificationsMockStream, start int, wait time.Duration, msg string) *protocol.NotificationReply {
	t.Helper()

	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if len(stream.replies)-start > 0 {
			return stream.replies[len(stream.replies)-1]
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("%s", msg)
	return nil
}

func TestRuntimeTaskCommandsIgnoreUnsupportedNamesWithoutImmediateReply(t *testing.T) {
	started := time.Now()
	defer func() {
		fmt.Printf(
			"cold-profile backend=go component=tasks elapsed_s=%.6f\n",
			time.Since(started).Seconds(),
		)
	}()

	client, stream := newRuntimeTaskParityFixture(t)
	start := len(stream.replies)

	client.handleActionTaskStart(stream, &protocol.Notification{
		Type: protocol.Action_TASK_START,
		Id:   1,
		Data: taskNotificationJSON(t, "unknown-task", map[string]interface{}{}),
	})
	assertNoReplyWithin(
		t,
		stream,
		start,
		80*time.Millisecond,
		"unsupported task start should not emit immediate reply",
	)

	client.handleActionTaskStop(stream, &protocol.Notification{
		Type: protocol.Action_TASK_STOP,
		Id:   2,
		Data: taskNotificationJSON(t, "unknown-task", map[string]interface{}{}),
	})
	assertNoReplyWithin(
		t,
		stream,
		start,
		80*time.Millisecond,
		"unsupported task stop should not emit immediate reply",
	)
}

func TestRuntimeTaskStartDuplicateReturnsErrorWithoutInitialStartedReply(t *testing.T) {
	started := time.Now()
	defer func() {
		fmt.Printf(
			"cold-profile backend=go component=tasks elapsed_s=%.6f\n",
			time.Since(started).Seconds(),
		)
	}()

	client, stream := newRuntimeTaskParityFixture(t)
	start := len(stream.replies)
	pid := strconv.Itoa(os.Getpid())
	data := map[string]interface{}{
		"pid":      pid,
		"interval": "5s",
	}

	client.handleActionTaskStart(stream, &protocol.Notification{
		Type: protocol.Action_TASK_START,
		Id:   7,
		Data: taskNotificationJSON(t, "pid-monitor", data),
	})
	assertNoReplyWithin(
		t,
		stream,
		start,
		80*time.Millisecond,
		"successful start should not emit immediate started reply",
	)

	client.handleActionTaskStart(stream, &protocol.Notification{
		Type: protocol.Action_TASK_START,
		Id:   8,
		Data: taskNotificationJSON(t, "pid-monitor", data),
	})
	reply := waitForReplyWithin(
		t,
		stream,
		start,
		time.Second,
		"duplicate start should emit a reply",
	)

	if len(stream.replies)-start != 1 {
		t.Fatalf("duplicate start should emit exactly one reply, got %d", len(stream.replies)-start)
	}
	if reply.Id != 8 {
		t.Fatalf("unexpected duplicate reply id: got=%d want=8", reply.Id)
	}
	if reply.Code != protocol.NotificationReplyCode_ERROR {
		t.Fatalf("unexpected duplicate reply code: got=%v want=%v", reply.Code, protocol.NotificationReplyCode_ERROR)
	}
	if !strings.Contains(reply.Data, "already exists") {
		t.Fatalf("duplicate reply should contain 'already exists', got %q", reply.Data)
	}

	client.handleActionTaskStop(stream, &protocol.Notification{
		Type: protocol.Action_TASK_STOP,
		Id:   9,
		Data: taskNotificationJSON(t, "pid-monitor", data),
	})
}
