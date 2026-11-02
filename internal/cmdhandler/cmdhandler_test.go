package cmdhandler_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/internal/cmdhandler"
)

func TestNoCmd(t *testing.T) {
	t.Parallel()

	err := cmdhandler.NoCmd(nil, nil)
	require.NoError(t, err, "NoCmd should return no error")
}

func TestZeroOrNArgs(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		argCount int
		args     []string

		wantErr bool
	}{
		"Zero args":      {},
		"Exactly N args": {argCount: 1, args: []string{"arg1"}},

		"Error with less than N args": {argCount: 2, args: []string{"arg1"}, wantErr: true},
		"Error with more than N args": {argCount: 2, args: []string{"arg1", "arg2", "arg3"}, wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cmd := &cobra.Command{}
			err := cmdhandler.ZeroOrNArgs(tc.argCount)(cmd, tc.args)
			if tc.wantErr {
				require.Error(t, err, "ZeroOrNArgs should return an error")
				return
			}
			require.NoError(t, err, "ZeroOrNArgs should return no error")
		})
	}
}

func TestNoValidArgs(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{}
	args, directive := cmdhandler.NoValidArgs(cmd, []string{"arg1", "arg2"}, "")

	require.Empty(t, args, "NoValidArgs should return no args")
	require.Equal(t, directive, cobra.ShellCompDirectiveNoFileComp, "NoValidArgs should return NoFileComp directive")
}

func TestRegisterAlias(t *testing.T) {
	t.Parallel()

	parent := &cobra.Command{
		Use: "parent",
	}
	child := &cobra.Command{
		Use:  "child",
		Long: "This is the aliased command",
	}

	cmdhandler.RegisterAlias(child, parent)

	// Find the alias command in the parent's commands
	var alias *cobra.Command
	for _, cmd := range parent.Commands() {
		if cmd.Use == "child" {
			alias = cmd
			break
		}
	}

	require.NotNil(t, alias, "Alias command not found")
	require.Equal(t, `This is the aliased command (Alias of "child")`, alias.Long, "Alias long description is incorrect")
	require.NotSame(t, child, alias, "Alias command should be a copy, but it points to the same command")
}
