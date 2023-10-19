package command_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/adsys/e2e/internal/command"
	"github.com/ubuntu/adsys/e2e/internal/inventory"
	"github.com/ubuntu/adsys/internal/testutils"
)

func TestAddFlags(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "inventory.yaml")
	cmd := command.New(mockAction, command.WithStateTransition(inventory.Null, inventory.TemplateCreated))

	args := []string{"my_command"}
	initOsArgs := os.Args
	defer func() { os.Args = initOsArgs }()
	os.Args = append(args, "--string", "test", "--bool", "--inventory-file", inventoryPath)

	var s string
	var b bool
	cmd.AddStringFlag(&s, "string", "", "")
	cmd.AddBoolFlag(&b, "bool", false, "")

	ret := cmd.Execute(context.Background())
	require.Zero(t, ret, "Setup: command.Execute should return 0")

	require.Equal(t, "test", s, "String flag should be set")
	require.True(t, b, "Bool flag should be set")
}

func TestInventory(t *testing.T) {
	tests := map[string]struct {
		fromState inventory.State
		toState   inventory.State

		existingInventory string

		wantErr    bool
		wantNoFile bool
	}{
		"From null state doesn't require existing data": {toState: inventory.BaseVMCreated},
		"From existing state requires existing data":    {fromState: inventory.BaseVMCreated, toState: inventory.TemplateCreated, existingInventory: "inventory_from_template_created"},
		"To null state doesn't write data":              {toState: inventory.Null, wantNoFile: true},

		"Error if inventory file is required and doesn't exist":  {fromState: inventory.TemplateCreated, wantErr: true},
		"Error if inventory state does not match expected state": {fromState: inventory.TemplateCreated, existingInventory: "inventory_from_template_created", wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.fromState == "" {
				tc.fromState = inventory.Null
			}
			if tc.toState == "" {
				tc.toState = inventory.Null
			}

			args := []string{"my_command"}
			initOsArgs := os.Args
			defer func() { os.Args = initOsArgs }()

			tempDir := t.TempDir()
			testutils.Copy(t, filepath.Join(testutils.TestFamilyPath(t)), filepath.Join(tempDir, "inventory"))
			if tc.existingInventory == "" {
				tc.existingInventory = "inventory.yaml"
			}
			inventoryPath := filepath.Join(tempDir, "inventory", tc.existingInventory)
			os.Args = append(args, "--inventory-file", inventoryPath)

			cmd := command.New(mockAction, command.WithStateTransition(tc.fromState, tc.toState))
			ret := cmd.Execute(context.Background())

			if tc.wantErr {
				require.NotZero(t, ret, "Execute should have returned an error but it didn't")
				return
			}

			if tc.wantNoFile {
				require.NoFileExists(t, inventoryPath, "Inventory file should not exist on the disk")
			} else {
				require.FileExists(t, inventoryPath, "Inventory file should exist on the disk")
			}

			require.Zero(t, ret, "Execute should have succeeded but it didn't")
			require.Equal(t, tc.toState, cmd.Inventory.State, "Inventory state should have been updated")
		})
	}
}

func TestExecute(t *testing.T) {
	tests := map[string]struct {
		action   func(ctx context.Context, cmd *command.Command) error
		validate func(ctx context.Context, cmd *command.Command) error

		wantErr bool
	}{
		"Action succeeds":               {},
		"Action and validation succeed": {validate: mockValidate},

		"Error when action fails":                    {action: mockFailingAction, wantErr: true},
		"Error when validation fails":                {validate: mockFailingValidate, wantErr: true},
		"Error when both action and validation fail": {action: mockFailingAction, validate: mockFailingValidate, wantErr: true},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			if tc.action == nil {
				tc.action = mockAction
			}

			var opts []command.Option
			if tc.validate != nil {
				opts = append(opts, command.WithValidateFunc(tc.validate))
			}

			args := []string{"my_command"}
			initOsArgs := os.Args
			defer func() { os.Args = initOsArgs }()
			os.Args = append(args, "--inventory-file", filepath.Join(t.TempDir(), "inventory.yaml"))

			cmd := command.New(tc.action, opts...)
			ret := cmd.Execute(context.Background())

			if tc.wantErr {
				require.NotZero(t, ret, "Execute should have returned an error but it didn't")
				return
			}
			require.Zero(t, ret, "Execute should have succeeded but it didn't")
		})
	}
}

func mockAction(_ context.Context, _ *command.Command) error { return nil }
func mockFailingAction(_ context.Context, _ *command.Command) error {
	return errors.New("requested error")
}

func mockValidate(_ context.Context, _ *command.Command) error { return nil }
func mockFailingValidate(_ context.Context, _ *command.Command) error {
	return errors.New("requested error")
}
