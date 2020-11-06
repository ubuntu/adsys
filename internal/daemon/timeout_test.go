package daemon_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/daemon"
	"google.golang.org/grpc"
)

func TestServerStartListenTimeout(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grpcRegister := &grpcServiceRegister{}

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"), daemon.WithTimeout(time.Duration(10*time.Millisecond)))
	require.NoError(t, err, "New should return the daemon handler")

	errs := make(chan error)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := d.Listen(); err != nil {
			errs <- err
		}
		close(errs)
		wg.Done()
	}()

	select {
	case <-time.After(time.Second):
		d.Quit()
		t.Fatalf("Server should have timed out, but it didn't")
	case err := <-errs:
		require.NoError(t, err, "No error from listen")
	}
	wg.Wait()
}

func TestServerDontTimeoutWithActiveRequest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grpcRegister := &grpcServiceRegister{}

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"), daemon.WithTimeout(time.Duration(10*time.Millisecond)))
	require.NoError(t, err, "New should return the daemon handler")

	errs := make(chan error)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := d.Listen(); err != nil {
			errs <- err
		}
		close(errs)
		wg.Done()
	}()

	info := &grpc.StreamServerInfo{FullMethod: "MyGRPCCall"}
	// simulate a new connection
	d.OnNewConnection(context.Background(), info)

	select {
	case <-time.After(100 * time.Millisecond):
	case err := <-errs:
		require.NoError(t, err, "Daemon exited prematurely: we had a request in flight. Exited with %v", err)
	}

	// connection ends
	d.OnDoneConnection(context.Background(), info)

	select {
	case <-time.After(time.Second):
		d.Quit()
		t.Fatalf("Server should have timed out, but it didn't")
	case err := <-errs:
		require.NoError(t, err, "No error from listen")
	}
	wg.Wait()
}

func TestServerDontTimeoutWithMultipleActiveRequests(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grpcRegister := &grpcServiceRegister{}

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"), daemon.WithTimeout(time.Duration(10*time.Millisecond)))
	require.NoError(t, err, "New should return the daemon handler")

	errs := make(chan error)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := d.Listen(); err != nil {
			errs <- err
		}
		close(errs)
		wg.Done()
	}()

	// simulate 2 connections end stop one
	info := &grpc.StreamServerInfo{FullMethod: "MyGRPCCall"}
	d.OnNewConnection(context.Background(), info)
	d.OnNewConnection(context.Background(), info)
	d.OnDoneConnection(context.Background(), info)

	select {
	case <-time.After(100 * time.Millisecond):
	case err := <-errs:
		require.NoError(t, err, "Daemon exited prematurely: we had a still one request in flight. Exited with %v", err)
	}

	// ending second connection
	d.OnDoneConnection(context.Background(), info)

	select {
	case <-time.After(time.Second):
		d.Quit()
		t.Fatalf("Server should have timed out, but it didn't")
	case err := <-errs:
		require.NoError(t, err, "No error from listen")
	}
	wg.Wait()
}
