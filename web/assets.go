package webassets

import (
	"embed"
)

// DistFS contains the pre-built frontend files.
//
//go:embed dist/*
var DistFS embed.FS
