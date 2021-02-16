package dconf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		keyType string
		value   string

		want string
	}{
		// string cases
		"simple quoted string":   {keyType: "s", value: "'hello world'", want: "'hello world'"},
		"simple unquoted string": {keyType: "s", value: "hello world", want: "'hello world'"},
		"empty quoted string":    {keyType: "s", value: "''", want: "''"},
		"empty unquoted string":  {keyType: "s", value: "", want: "''"},

		"one quote":         {keyType: "s", value: "'", want: `'\''`},
		"one escaped quote": {keyType: "s", value: `\'`, want: `'\''`},

		"quoted string with quotes":                       {keyType: "s", value: "'this isn't a quote'", want: `'this isn\'t a quote'`},
		"unquoted string with quotes":                     {keyType: "s", value: "this isn't a quote", want: `'this isn\'t a quote'`},
		"string with escaped quotes":                      {keyType: "s", value: `this isn\'t a quote`, want: `'this isn\'t a quote'`},
		"string with multiple backslashes escaped quotes": {keyType: "s", value: `this isn\\\'t a quote`, want: `'this isn\\\'t a quote'`},
		"string with two backslashes don’t escape quotes": {keyType: "s", value: `this isn\\'t a quote`, want: `'this isn\\\'t a quote'`},

		// boolean cases
		"simple boolean true":             {keyType: "b", value: "true", want: "true"},
		"weird case true":                 {keyType: "b", value: "tRuE", want: "true"},
		"with spaces":                     {keyType: "b", value: "  true  ", want: "true"},
		"yes transformed to boolean":      {keyType: "b", value: "yes", want: "true"},
		"y transformed to boolean":        {keyType: "b", value: "y", want: "true"},
		"on transformed to boolean":       {keyType: "b", value: "on", want: "true"},
		"simple boolean false":            {keyType: "b", value: "false", want: "false"},
		"weird case false":                {keyType: "b", value: "fAlSe", want: "false"},
		"no transformed to boolean":       {keyType: "b", value: "no", want: "false"},
		"n transformed to boolean":        {keyType: "b", value: "n", want: "false"},
		"off transformed to boolean":      {keyType: "b", value: "off", want: "false"},
		"non supported is reported as is": {keyType: "b", value: "nonboolean", want: "nonboolean"},

		// as cases
		"simple unquoted as":                               {keyType: "as", value: "[aa, bb, cc]", want: "['aa', 'bb', 'cc']"},
		"simple quoted as":                                 {keyType: "as", value: "['aa', 'bb', 'cc']", want: "['aa', 'bb', 'cc']"},
		"simple as with no spaces":                         {keyType: "as", value: "[aa,bb,cc]", want: "['aa', 'bb', 'cc']"},
		"as with spaces inside":                            {keyType: "as", value: "[aa   ,bb,   cc]", want: "['aa', 'bb', 'cc']"},
		"as without leading [":                             {keyType: "as", value: "aa,bb,cc]", want: "['aa', 'bb', 'cc']"},
		"as without ending ]":                              {keyType: "as", value: "[aa,bb,cc", want: "['aa', 'bb', 'cc']"},
		"as with leading and ending spaces and no []":      {keyType: "as", value: "    aa,bb,cc   ", want: "['aa', 'bb', 'cc']"},
		"as with leading and ending spaces and  []":        {keyType: "as", value: "    [aa,bb,cc]   ", want: "['aa', 'bb', 'cc']"},
		"as simple quoted as with spaces":                  {keyType: "as", value: "      ['aa', 'bb', 'cc']    ", want: "['aa', 'bb', 'cc']"},
		"as empty elements separated with commas are kept": {keyType: "as", value: "[aa,bb,,cc]", want: "['aa', 'bb', '', 'cc']"},

		"as partially quoted can lead to unexpect result":                  {keyType: "as", value: "[aa,'bb',cc]", want: `['aa', '\'bb\'', 'cc']`},
		"as partially quoted with comma can lead to unexpected result":     {keyType: "as", value: "[aa,'b,b',cc]", want: `['aa', '\'b', 'b\'', 'cc']`},
		"as partially quoted unbalanced start can lead to unexpect result": {keyType: "as", value: "['aa,'bb',cc]", want: `['\'aa', '\'bb\'', 'cc']`},
		"as partially quoted unbalanced end can lead to unexpect result":   {keyType: "as", value: "[aa,'bb',cc']", want: `['aa', '\'bb\'', 'cc\'']`},
		"as wrongly quoted will consider comma as part of the string":      {keyType: "as", value: "['aa,'bb',cc']", want: `['aa,\'bb\',cc']`},
		"as with weird composition inception will be quoted":               {keyType: "as", value: "[value1, ] value2]", want: `['value1', '] value2']`},
		"as with empty quoted can lead to unexpect result":                 {keyType: "as", value: "[aa,'bb',cc]", want: `['aa', '\'bb\'', 'cc']`},

		"Multi-lines as unquoted":                                                   {keyType: "as", value: "aa\nbb\ncc", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as quoted":                                                     {keyType: "as", value: "'aa'\n'bb'\n'cc'", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with spaces inside":                                         {keyType: "as", value: "aa   \nbb\n   cc", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with leading and trailing brackets":                         {keyType: "as", value: "[aa\nbb\ncc]", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as and single line mix, unquoted":                              {keyType: "as", value: "aa,bb\ncc", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as and single line mix, quoted":                                {keyType: "as", value: "'aa','bb'\n'cc'", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with quoted ',' is supported":                               {keyType: "as", value: "'aa,bb'\n'cc'", want: "['aa,bb', 'cc']"},
		"Multi-lines as with all unquoted ',' will split":                           {keyType: "as", value: "aa,bb\ncc", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with empty lines strips empty elements":                     {keyType: "as", value: "aa\n\ncc", want: "['aa', 'cc']"},
		"Multi-lines as with consecutive empty lines strip empty elements":          {keyType: "as", value: "aa\n\n\n\ncc", want: "['aa', 'cc']"},
		"Multi-lines as with explicit empty element":                                {keyType: "as", value: "'aa'\n''\n'cc'", want: "['aa', '', 'cc']"},
		"Multi-lines as with leading or trailing empty lines are ignored":           {keyType: "as", value: "\n\n\n\naa\nbb\ncc\n\n\n\n\n", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with leading or trailing empty lines before [] are ignored": {keyType: "as", value: "[\n\n\n\naa\nbb\ncc\n\n\n\n\n]", want: "['aa', 'bb', 'cc']"},
		"Multi-lines as with leading or trailing empty lines after [] are ignored":  {keyType: "as", value: "\n\n\n\n[aa\nbb\ncc]\n\n\n\n\n", want: "['aa', 'bb', 'cc']"},

		// ai cases
		"simple ai":                                        {keyType: "ai", value: "[1, 2, 3]", want: "[1, 2, 3]"},
		"simple ai with no spaces":                         {keyType: "ai", value: "[1,2,3]", want: "[1, 2, 3]"},
		"ai with spaces inside":                            {keyType: "ai", value: "[1   ,2,   3]", want: "[1, 2, 3]"},
		"ai without leading [":                             {keyType: "ai", value: "1,2,3]", want: "[1, 2, 3]"},
		"ai without ending ]":                              {keyType: "ai", value: "[1,2,3", want: "[1, 2, 3]"},
		"ai with leading and ending spaces and no []":      {keyType: "ai", value: "    1,2,3   ", want: "[1, 2, 3]"},
		"ai with leading and ending spaces and  []":        {keyType: "ai", value: "    [1,2,3]   ", want: "[1, 2, 3]"},
		"ai empty elements separated with commas are kept": {keyType: "ai", value: "1,,3", want: "[1, , 3]"},

		"Multi-lines ai":                                                            {keyType: "ai", value: "1\n2\n3", want: "[1, 2, 3]"},
		"Multi-lines ai with spaces inside":                                         {keyType: "ai", value: "1\n   2\n   3", want: "[1, 2, 3]"},
		"Multi-lines ai with leading and trailing brackets":                         {keyType: "ai", value: "[1\n2\n3]", want: "[1, 2, 3]"},
		"Multi-lines ai with all unquoted ',' will split":                           {keyType: "ai", value: "1,2\n3", want: "[1, 2, 3]"},
		"Multi-lines ai with empty lines strips empty element":                      {keyType: "ai", value: "1\n\n3", want: "[1, 3]"},
		"Multi-lines ai with consecutive empty lines strips empty element":          {keyType: "ai", value: "1\n\n\n\n3", want: "[1, 3]"},
		"Multi-lines ai with leading or trailing empty lines are ignored":           {keyType: "ai", value: "\n\n\n\n1\n2\n3\n\n\n\n\n", want: "[1, 2, 3]"},
		"Multi-lines ai with leading or trailing empty lines before [] are ignored": {keyType: "ai", value: "[\n\n\n\n1\n2\n3\n\n\n\n\n]", want: "[1, 2, 3]"},
		"Multi-lines ai with leading or trailing empty lines after [] are ignored":  {keyType: "ai", value: "\n\n\n\n[1\n2\n3]\n\n\n\n\n", want: "[1, 2, 3]"},

		// Unmanaged cases
		"unmanaged types are returned as is": {keyType: "xxx", value: "hello [ %x bar 🤪", want: "hello [ %x bar 🤪"},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := normalizeValue(tc.keyType, tc.value)
			assert.Equal(t, tc.want, got, "normalizeValue returned expected value")
		})
	}
}
