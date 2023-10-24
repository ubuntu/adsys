// Package docs embeds structured adsys documentation.
package docs

import (
	"embed"
)

// Dir is the embedded directory containing documentation
// Only embed structured documentation.
//
//go:embed index.md tutorial/*.md how-to/*.md explanation/*.md reference/*.md
var Dir embed.FS

// Root of ReadTheDoc
const RTDRootURL = "https://canonical-adsys.readthedocs-hosted.com/en/documentation_bootstrap"
