# Changelog

All notable changes to this project will be documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

Per-version release notes for tagged releases are published on the [GitHub Releases page](https://github.com/WYRE-AI/dnsfilter-mcp/releases) - `semantic-release` generates them from commit history at release time.

## [Unreleased]

### Added

- Initial v1 release: 57 read-only tools covering DNSFilter's organizations, networks (sites), filtering policies, content/application categories, custom block pages, organization-usage metrics, and the full 38-operation traffic/threat reporting surface. Static API-key authentication, sent as the raw `Authorization` header value (no `Bearer` prefix, per DNSFilter's own API docs). Every tool maps 1:1 to a documented `GET` operation in DNSFilter's own published OpenAPI spec (`api.dnsfilter.com/docs.json`); every write/mutation endpoint on every in-scope resource is deliberately excluded. See README's Scope and Authentication sections for the full excluded-endpoint accounting and the two-tier credential-scope confidence split.
