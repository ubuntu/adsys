package adsys_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestPullRequestTargetWorkflowsCancelPerPullRequest ensures that a workflow triggered by
// pull_request_target only cancels runs of the same pull request.
//
// On pull_request_target, github.ref is the base branch of the pull request, so a
// concurrency group built on it is shared by every pull request targeting that branch:
// with cancel-in-progress, a run for one pull request cancels the runs of the others.
func TestPullRequestTargetWorkflowsCancelPerPullRequest(t *testing.T) {
	t.Parallel()

	workflows, err := filepath.Glob(filepath.Join(".github", "workflows", "*.y*ml"))
	require.NoError(t, err, "Setup: can't list the workflows")
	require.NotEmpty(t, workflows, "Setup: no workflow found")

	for _, path := range workflows {
		content, err := os.ReadFile(path)
		require.NoError(t, err, "Setup: can't read %s", path)

		var w struct {
			On          yaml.Node `yaml:"on"`
			Concurrency yaml.Node `yaml:"concurrency"`
		}
		require.NoError(t, yaml.Unmarshal(content, &w), "Setup: can't parse %s", path)

		if !hasTrigger(w.On, "pull_request_target") {
			continue
		}
		group := concurrencyGroup(w.Concurrency)
		if group == "" {
			continue
		}
		require.True(t, strings.Contains(group, "github.event.pull_request.number"),
			"%s runs on pull_request_target: its concurrency group %q should be per pull request (github.event.pull_request.number), as github.ref is the base branch there",
			path, group)
	}
}

// hasTrigger reports whether the "on" section of a workflow, in any of its forms
// (a single event, a list or a map of events), contains event.
func hasTrigger(on yaml.Node, event string) bool {
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == event
	case yaml.SequenceNode:
		for _, n := range on.Content {
			if n.Value == event {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(on.Content); i += 2 {
			if on.Content[i].Value == event {
				return true
			}
		}
	}
	return false
}

// concurrencyGroup returns the group of a concurrency section, given either as a
// plain string or as a map with a group key.
func concurrencyGroup(c yaml.Node) string {
	switch c.Kind {
	case yaml.ScalarNode:
		return c.Value
	case yaml.MappingNode:
		for i := 0; i < len(c.Content); i += 2 {
			if c.Content[i].Value == "group" {
				return c.Content[i+1].Value
			}
		}
	}
	return ""
}
