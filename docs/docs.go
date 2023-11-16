// Package docs embeds structured adsys documentation.
package docs

import (
	"embed"
)

// Dir is the embedded directory containing documentation.
// Only embed structured documentation.
//
//go:embed index.md how-to/*.md explanation/*.md reference/*.md
var Dir embed.FS

// RTDRootURL is the root url of ReadTheDoc adsys documentation.
const RTDRootURL = "https://canonical-adsys.readthedocs-hosted.com/en/latest"
