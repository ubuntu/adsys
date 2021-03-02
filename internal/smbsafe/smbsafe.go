package smbsafe

/*
libsmbclient overrides sigchild without setting SA_ONSTACK
It means that any cmd.Wait() would segfault when ran concurrently with this.

This package will handle globally (sigh) states to restore sig child and exec safely.
We use the want and done channels to held and enter safely in one of the mode. Multiple
requests in the same mode can be executed in parallel.
*/

/*
#include <stdio.h>
#include <signal.h>
#include <string.h>

struct sigaction orig_action;

void captureoriginsigchild() {
	sigaction(SIGCHLD, NULL, &orig_action);
}

void restoresigchild() {
	struct sigaction modified_action;
	sigaction(SIGCHLD, &orig_action, &modified_action);
}
*/
import "C"

var (
	wantSmb, doneSmb   chan struct{}
	wantExec, doneExec chan struct{}
)

// This goroutine allows to avoid libsmbclient overriding sigchild while we are executing a command,
// as .Wait() would then segfault.
// Please use the Wait/Done functions to wrap any Exec or smb calls.
func init() {
	C.captureoriginsigchild()

	wantSmb, doneSmb, wantExec, doneExec = make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		for {
			// switch between Samba and Exec mode
			select {
			case <-wantSmb:
				numSmb := 1
				// wait for all samba (maybe new ones can be created) to be done
				for {
					select {
					case <-wantSmb:
						numSmb++
					case <-doneSmb:
						numSmb--
					}

					if numSmb == 0 {
						break
					}
				}
				C.restoresigchild()
			case <-wantExec:
				numExec := 1
				// wait for all execs (maybe new ones can be created) to be done
				for {
					select {
					case <-wantExec:
						numExec++
					case <-doneExec:
						numExec--
					}

					if numExec == 0 {
						break
					}
				}
			}
		}
	}()
}

// WaitSmb will block until with can execute multiple smb command concurrently.
func WaitSmb() {
	wantSmb <- struct{}{}
}

// DoneSmb will signal that execution of the smb command is done.
func DoneSmb() {
	doneSmb <- struct{}{}
}

// WaitExec will block until with can execute multiple commands concurrently.
func WaitExec() {
	wantExec <- struct{}{}
}

// DoneExec will signal that execution of the command is done.
func DoneExec() {
	doneExec <- struct{}{}
}
