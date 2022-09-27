package mount

import (
	"fmt"

	"github.com/ubuntu/adsys/internal/policies/entry"
)

// GetEntries generates entries to be used in tests.
func GetEntries(nEntries, nErrored, nValues, nDuplicated int, sep []string) []entry.Entry {
	entries := []entry.Entry{}
	c := 0
	for i := 0; i < nEntries; i++ {
		if i < nErrored {
			e := entry.Entry{Err: fmt.Errorf("this entry has an error")}
			entries = append(entries, e)
			continue
		}

		e := entry.Entry{Key: fmt.Sprintf("mount/%d", i)}
		dup := 0
		value := "protocol://domain.com/mount-%d-path"
		for n := 0; n < nValues; n++ {
			v := fmt.Sprintf(value, c)
			c++
			if dup < nDuplicated {
				v = fmt.Sprintf(value, 1000)
				dup++
			}
			e.Value += v + sep[n%len(sep)]
		}

		entries = append(entries, e)
	}

	return entries
}
