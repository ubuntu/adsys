package ad

import (
	"errors"
	"os"
	"os/exec"
)

var (
	WithRunDir      = withRunDir
	WithCacheDir    = withCacheDir
	WithoutKerberos = withoutKerberos
	WithKinitCmd    = withKinitCmd
	WithGPOListCmd  = withGPOListCmd
)

func (ad *AD) GpoCacheDir() string {
	return ad.gpoCacheDir
}
func (ad *AD) Krb5CacheDir() string {
	return ad.krb5CacheDir
}

func (ad *AD) ResetGpoListCmdWith(cmd *exec.Cmd) {
	ad.gpoListCmd = cmd
}

type MockKinit struct {
	Failing bool
}

func (m MockKinit) CombinedOutput() ([]byte, error) {
	if m.Failing {
		return []byte("My error message on stderr"), errors.New("Exit 1")
	}
	return nil, nil
}

type MockKinitWithComputer struct {
	HostKrb5CCName string
}

func (m MockKinitWithComputer) CombinedOutput() ([]byte, error) {
	if m.HostKrb5CCName != "" {
		f, err := os.Create(m.HostKrb5CCName)
		if err != nil {
			return []byte("Setup: failed to open host krb5 cache file"), err
		}
		if _, err = f.Write([]byte("krb5CCcontent")); err != nil {
			return []byte("Setup: failed to write to host krb5 cache file"), err
		}

		if err = f.Close(); err != nil {
			return []byte("Setup: failed to close host krb5 cache file"), err
		}
	}
	return nil, nil
}
