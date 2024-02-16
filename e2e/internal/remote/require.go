package remote

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// RequireEqual runs the given command and compares its output to the expected value.
func (c Client) RequireEqual(ctx context.Context, cmd string, expected string) error {
	out, err := c.Run(ctx, cmd)
	if err != nil {
		return err
	}

	if strings.TrimSpace(string(out)) != expected {
		return fmt.Errorf("expected %q, got %q", expected, string(out))
	}

	return nil
}

// RequireContains runs the given command and checks if the output contains the expected value.
func (c Client) RequireContains(ctx context.Context, cmd string, expected string) error {
	out, err := c.Run(ctx, cmd)
	if err != nil {
		return err
	}

	if !strings.Contains(strings.TrimSpace(string(out)), expected) {
		return fmt.Errorf("expected %q to include %q", expected, string(out))
	}

	return nil
}

// RequireEmpty runs the given command and returns an error if the output is not empty.
func (c Client) RequireEmpty(ctx context.Context, cmd string) error {
	out, err := c.Run(ctx, cmd)
	if err != nil {
		return err
	}

	if strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("expected empty output, got %q", string(out))
	}

	return nil
}

// RequireNotEmpty runs the given command and returns an error if the output is empty.
func (c Client) RequireNotEmpty(ctx context.Context, cmd string) error {
	if err := c.RequireEmpty(ctx, cmd); err == nil {
		return errors.New("expected non-empty output")
	}

	return nil
}

// RequireFileExists returns an error if the given file does not exist.
func (c Client) RequireFileExists(ctx context.Context, filepath string) error {
	_, err := c.Run(ctx, fmt.Sprintf("test -f %q", filepath))
	if err != nil {
		return fmt.Errorf("expected file %q to exist", filepath)
	}

	return nil
}

// RequireNoFileExists returns an error if the given file exists.
func (c Client) RequireNoFileExists(ctx context.Context, filepath string) error {
	if err := c.RequireFileExists(ctx, filepath); err == nil {
		return fmt.Errorf("expected file %q to not exist", filepath)
	}

	return nil
}
