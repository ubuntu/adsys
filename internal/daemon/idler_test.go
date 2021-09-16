package daemon_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/daemon"
	"google.golang.org/grpc"
)

func TestServerStartListenTimeout(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grpcRegister := &grpcServiceRegister{}

	timeout := 10 * time.Millisecond
	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"), daemon.WithTimeout(timeout))
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
	case <-time.After(5 * time.Second):
		d.Quit(false)
		t.Fatalf("Server should have timed out, but it didn't")
	case err := <-errs:
		require.NoError(t, err, "No error from listen")
	}
	wg.Wait()
	require.Equal(t, timeout, d.Timeout(), "Report expected timeout")
}

func TestServerDontTimeoutWithActiveRequest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grpcRegister := &grpcServiceRegister{}

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"), daemon.WithTimeout(10*time.Millisecond))
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
	case <-time.After(5 * time.Second):
		d.Quit(false)
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

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"), daemon.WithTimeout(10*time.Millisecond))
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
	case <-time.After(5 * time.Second):
		d.Quit(false)
		t.Fatalf("Server should have timed out, but it didn't")
	case err := <-errs:
		require.NoError(t, err, "No error from listen")
	}
	wg.Wait()
}

func TestServerChangeTimeout(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grpcRegister := &grpcServiceRegister{}

	// initial timeout is 10 millisecond
	start := time.Now()
	currentTimeout := 10 * time.Millisecond
	changedTimeout := 50 * time.Millisecond
	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"), daemon.WithTimeout(currentTimeout))
	require.NoError(t, err, "New should return the daemon handler")
	require.Equal(t, currentTimeout, d.Timeout(), "Report expected timeout")

	// change it to 50 Millisecond which should be the minimum time of wait
	d.ChangeTimeout(changedTimeout)
	require.Equal(t, changedTimeout, d.Timeout(), "Report modified timeout")

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

	// check initial timeout of 50 milliseconds min
	select {
	case <-time.After(5 * time.Second):
		d.Quit(false)
		t.Fatalf("Server should have timed out, but it didn't")
	case err := <-errs:
		require.NoError(t, err, "No error from listen")
	}

	assert.True(t, time.Now().After(start.Add(50*time.Millisecond)), "Wait more than initial timeout and changed timeout")

	wg.Wait()
}

func TestServerDoubleQuit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	grpcRegister := &grpcServiceRegister{}

	d, err := daemon.New(grpcRegister.registerGRPCServer, filepath.Join(dir, "test.sock"))
	require.NoError(t, err, "New should return the daemon handler")

	errs := make(chan error, 1)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if err := d.Listen(); err != nil {
			errs <- err
		}
		close(errs)
		wg.Done()
	}()

	<-time.After(10 * time.Millisecond)

	// No error triggered by quitting twice
	d.Quit(false)
	d.Quit(false)

	wg.Wait()
	err = <-errs
	require.NoError(t, err, "No error from listen")
}
