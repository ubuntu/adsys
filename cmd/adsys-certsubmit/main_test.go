package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCertmongerCAName(t *testing.T) {
	t.Run("flag takes precedence", func(t *testing.T) {
		t.Setenv("CERTMONGER_CA_NICKNAME", "env-ca")
		require.Equal(t, "flag-ca", certmongerCAName("flag-ca"))
	})

	t.Run("certmonger nickname fallback", func(t *testing.T) {
		t.Setenv("CERTMONGER_CA_NICKNAME", "env-ca")
		require.Equal(t, "env-ca", certmongerCAName(""))
	})

	t.Run("alternate certmonger name fallback", func(t *testing.T) {
		t.Setenv("CERTMONGER_CA_NAME", "env-ca")
		require.Equal(t, "env-ca", certmongerCAName(""))
	})
}
