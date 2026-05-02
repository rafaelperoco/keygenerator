package main

// Build-time identity, set via -ldflags="-X 'main.version=...' -X 'main.commit=...' -X 'main.buildDate=...'".
// Defaults reflect a development build.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)
