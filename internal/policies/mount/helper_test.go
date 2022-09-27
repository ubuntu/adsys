package mount

import (
	"fmt"

	"github.com/ubuntu/adsys/internal/policies/entry"
)

// GetEntries generates entries to be used in tests.
func GetEntries(nEntries, nErrored int) []entry.Entry {
	entries := []entry.Entry{}

	for i := 0; i < nEntries; i++ {

		e := entry.Entry{
			Key:      "mount",
			Value:    fmt.Sprintf("protocol://domain.com/entry-%d", i+1),
			Disabled: false,
			Meta:     "",
			Strategy: "",
			Err:      nil,
		}

		if i < nErrored {
			e.Err = fmt.Errorf("this entry has an error")
		}

		entries = append(entries, e)
	}

	return entries
}
