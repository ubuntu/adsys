package smbsafe_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/smbsafe"
)

var waitTime = time.Millisecond * 10

func TestExclusiveLockExec(t *testing.T) {
	// first lock takes it immediately
	now := time.Now()
	smbsafe.WaitExec()
	shouldNotHaveWaited(t, now)

	// WaitSmb should wait
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		now := time.Now()
		smbsafe.WaitSmb()
		shouldHaveWaited(t, now)
		smbsafe.DoneSmb()
	}()

	// Wait more than minimum duration time to release the lock
	time.Sleep(waitTime)

	smbsafe.DoneExec()

	wg.Wait()
}

func TestExclusiveLockSmb(t *testing.T) {
	// first lock takes it immediately
	now := time.Now()
	smbsafe.WaitSmb()
	shouldNotHaveWaited(t, now)

	// WaitExec should wait
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		now := time.Now()
		smbsafe.WaitExec()
		shouldHaveWaited(t, now)
		smbsafe.DoneExec()
	}()

	// Wait more than minimum duration time to release the lock
	time.Sleep(waitTime)

	smbsafe.DoneSmb()

	wg.Wait()
}

func TestMultipleExecLocksOnlyReleaseOnLast(t *testing.T) {
	// first lock takes it immediately
	now := time.Now()
	smbsafe.WaitExec()
	shouldNotHaveWaited(t, now)
	smbsafe.WaitExec()
	shouldNotHaveWaited(t, now)
	smbsafe.WaitExec()
	shouldNotHaveWaited(t, now)

	// WaitSmb should wait
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		now := time.Now()
		smbsafe.WaitSmb()
		shouldHaveWaited(t, now)
		smbsafe.DoneSmb()
	}()

	smbsafe.DoneExec()
	smbsafe.DoneExec()

	// Only wait before latest unlock
	time.Sleep(waitTime)
	smbsafe.DoneExec()

	wg.Wait()
}

func TestMultipleSmbLocksOnlyReleaseOnLast(t *testing.T) {
	// first lock takes it immediately
	now := time.Now()
	smbsafe.WaitSmb()
	shouldNotHaveWaited(t, now)
	smbsafe.WaitSmb()
	shouldNotHaveWaited(t, now)
	smbsafe.WaitSmb()
	shouldNotHaveWaited(t, now)

	// WaitExec should wait
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		now := time.Now()
		smbsafe.WaitExec()
		shouldHaveWaited(t, now)
		smbsafe.DoneExec()
	}()

	smbsafe.DoneSmb()
	smbsafe.DoneSmb()

	// Only wait before latest unlock
	time.Sleep(waitTime)
	smbsafe.DoneSmb()

	wg.Wait()
}

func shouldHaveWaited(t *testing.T, startpoint time.Time) {
	t.Helper()

	require.Less(t, int64(waitTime), int64(time.Since(startpoint)), "Should have waited")
}

func shouldNotHaveWaited(t *testing.T, startpoint time.Time) {
	t.Helper()

	require.Less(t, int64(time.Since(startpoint)), int64(waitTime), "Shouldn’t have waited")
}
