# DNSFilter MCP Server

MCP server for [DNSFilter](https://www.dnsfilter.com/)'s DNS security/filtering API - organizations, networks (sites), filtering policies, content/application categories, custom block pages, and the full traffic/threat reporting surface, for AI assistants and the WYRE Conduit gateway.

## Scope

**This is a deliberately narrow, read-only v1 surface, hard-scoped to organizations, networks, policies, categories, block pages, and reporting.** DNSFilter's REST API (`api.dnsfilter.com`) has 217 documented paths across a much broader surface - MSP/distributor management, billing, users, roaming-client agents, enterprise SSO connections, API key management, scheduled reports, and more. None of that is implemented here, by design, not by oversight. Every tool in this connector maps 1:1 to a real, documented `GET` operation in DNSFilter's own published OpenAPI spec (`https://api.dnsfilter.com/docs.json`) - there is no write, update, or delete tool anywhere in this codebase.

**Hard-excluded (every write/mutation operation on every in-scope resource) - never implemented:**
- `POST/PATCH/DELETE /v1/organizations*` (create, bulk_update, promote_to_msp, update, cancel, destroy) - organization mutations.
- `POST/PATCH/DELETE /v1/networks*` (create, bulk_create/update/destroy, update, destroy, secret_key rotate/revoke/generate) - network mutations, including LAN IP and subnet writes.
- `POST/PATCH/DELETE /v1/policies*` (create, update, destroy, application_update, add/remove_allowed_application, add/remove_blacklist_category, add/remove_blacklist_domain, add/remove_blocked_application, add/remove_whitelist_domain, permissive_mode update) and all of `/v1/policies/bulk/*` (bulk allow/block-list add/remove) and `/v1/policy_ips` writes - every policy-content mutation.
- `POST/DELETE /v1/block_pages*` (create, destroy) and `PATCH /v1/block_pages/{id}` (update) - block-page mutations.
- Every write endpoint on resources this connector doesn't otherwise touch at all: API keys (`create`/`destroy`/`revoke`), users and organization users (`create`/`update`/`destroy`/`resend_invite`), billing/invoices, distributors (MSP/sub-org provisioning, SKUs, cancellation), enterprise SSO connections, scheduled policies/reports, roaming-client user-agents (bulk delete/update/cleanup, dequeue-uninstall), domain notes, IP/MAC address management, and trials.

They can be added as a follow-up if there's demand, after a deliberate scope decision - not by default.

**Deferred (read-only, not implemented in this v1 - not a security exclusion):** a handful of GET-only sub-resources and dashboard-adjacent endpoints exist under the same resource groups this connector covers, but aren't wired up yet: network subnets (`GET /v1/networks/{id}/subnets*`), network LAN IPs (`GET /v1/networks/{id}/lan_ips*`), policy IPs (`GET /v1/policy_ips*`), the unpaginated `*/all` variants of every list endpoint (redundant with the paginated list tool), and administrative `*/counts` endpoints. These can be added later without any scope-policy change, since they're already read-only.

## Authentication

DNSFilter authenticates with a static **API key**, generated in the DNSFilter dashboard under **Account Settings -> Security -> API Keys** (an account supports up to 5 active keys at a time; see [DNSFilter's own API Keys article](https://help.dnsfilter.com/hc/en-us/articles/21169189058323-API-Keys)). Unlike most sibling WYRE Conduit connectors, the key is sent as the **raw header value** - `Authorization: <key>`, with **no `Bearer` prefix** - per DNSFilter's own API docs: *"Authentication is done by setting the Authorization request header. The header value is the API key itself. For example: `Authorization: eyJ...`"*.

### Credential scope: two separate claims, at deliberately different confidence levels

- **Structurally verified (checked directly, stated with full confidence):** this connector's own code makes zero mutating calls - every function in `client.ts` is a `GET`, and no `POST`/`PUT`/`PATCH`/`DELETE` call exists anywhere in `src/` (enforced by `tool-scope.test.ts`'s forbidden-token check). Also structurally verified, directly against DNSFilter's own published OpenAPI spec (`api.dnsfilter.com/docs.json`, fetched directly): an API key is generated **per user account** (the `ApiKey` resource schema carries a `user_id` field) and its own creation request (`ApiKeyCreateSpec`) accepts only `name` and `expiry` - **there is no scope/role/permission field chosen at key-creation time**. A key's effective capability is therefore inherited from whatever role the DNSFilter user account it was generated under holds, not selected independently when the key itself is created. That same spec's `Membership`/`OrganizationUser` role enums explicitly include a `"read_only"` value alongside `"administrator"` (and, on the MSP/distributor membership shape, alongside `"network_administrator"`/`"network_support"`/`"support"`) - so a genuinely restricted DNSFilter user role is a first-class, documented concept in the API itself, not just dashboard-UI copy.
- **Vendor-documented, not independently verified (hedged deliberately):** DNSFilter's own help center separately describes a dashboard-level **Read Only** user role ("Users with more restrictive roles like Read Only... have hidden dashboard tabs and panels"). Combined with the structural finding above, generating an API key under a dedicated Read-Only-role user account *should* yield a key whose calls DNSFilter's API server rejects for any write endpoint - but whether the API actually **enforces** that role server-side against write calls (versus the restriction being dashboard-UI-only) has not been tested by WYRE. Nobody sent a live write call against a Read-Only-role key to confirm, correctly: that would be a mutating test against a real account, not something to run without consent. **Do not read this README as having established that a Read-Only-role API key cannot perform writes against DNSFilter's API** - only that (a) DNSFilter's spec models a `read_only` role as a real, first-class concept, and (b) this connector's own code never attempts a write regardless of which key it's given.

In gateway mode the key arrives per-request via the `X-DNSFilter-Api-Key` header; in local/stdio mode it's read once from `DNSFILTER_API_KEY`.

## Configuration

| Env var | Description |
|---|---|
| `DNSFILTER_API_KEY` | DNSFilter API key, generated in the DNSFilter dashboard. |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default, reads the var above) or `gateway` (credential arrives per-request via the `X-DNSFilter-Api-Key` header, injected by the Conduit gateway). |
| `CONDUIT_S2S_SECRET` | When set, the HTTP transport requires a valid `X-Gateway-S2S` header (Conduit sidecar auth) on every `/mcp` request. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

## Tools

57 read-only tools, one per documented DNSFilter `GET` operation across six resource groups.

### Organizations
- `dnsfilter_list_organizations` - list organizations visible to this API key.
- `dnsfilter_get_organization` - get one organization's basic information.
- `dnsfilter_get_organization_settings` - get organization-level settings.

### Networks
- `dnsfilter_list_networks` - list networks (sites/locations).
- `dnsfilter_get_network` - get one network's basic information.
- `dnsfilter_lookup_network_by_ip` - find the network associated with a source IP address.
- `dnsfilter_get_networks_geo` - get every network's geo/location metadata only.

### Policies
- `dnsfilter_list_policies` - list filtering policies.
- `dnsfilter_get_policy` - get one policy's full configuration (allow/block lists, categories, applications).
- `dnsfilter_get_application_policies` - get which policies allow/block a specific application.
- `dnsfilter_get_policy_permissive_mode` - get whether a policy has permissive (monitor-only) mode enabled.

### Categories
- `dnsfilter_list_categories` - list content-filtering categories.
- `dnsfilter_get_category` - get one content category's details and hierarchy.
- `dnsfilter_list_application_categories` - list application categories.
- `dnsfilter_get_application_category` - get one application category's details.

### Block Pages
- `dnsfilter_list_block_pages` - list custom block pages.
- `dnsfilter_get_block_page` - get one custom block page's configuration.

### Metrics
- `dnsfilter_get_organization_usage` - get organization usage (plan, users, total requests) over a date range.
- `dnsfilter_get_organization_usage_detailed` - get the detailed per-metric breakdown of organization usage.

### Traffic Reports

DNSFilter's entire reporting surface is `GET`-only, so all 38 documented report operations are implemented with no curation:

- `dnsfilter_get_qps`, `dnsfilter_get_qps_active_agents`, `dnsfilter_get_qps_active_organizations` - queries-per-second time series.
- `dnsfilter_get_query_logs` - raw DNS query log entries (domain, requester, category, allow/block result). The most granular, PII-bearing report this connector exposes.
- `dnsfilter_get_top_agents`, `dnsfilter_get_top_application_categories`, `dnsfilter_get_top_categories`, `dnsfilter_get_top_collections`, `dnsfilter_get_top_domains`, `dnsfilter_get_top_networks`, `dnsfilter_get_top_organizations_requests`, `dnsfilter_get_top_users` - "top N" breakdowns by traffic volume.
- `dnsfilter_get_total_applications_agents_stats`, `dnsfilter_get_total_applications_collections_stats`, `dnsfilter_get_total_applications_networks_stats`, `dnsfilter_get_total_applications_stats`, `dnsfilter_get_total_applications_users_stats` - application request-count totals, broken out by dimension.
- `dnsfilter_get_total_categories`, `dnsfilter_get_total_categories_organizations`, `dnsfilter_get_total_category_stats` - content-category request totals.
- `dnsfilter_get_total_client_stats`, `dnsfilter_get_total_deployments`, `dnsfilter_get_total_roaming_clients` - client/deployment counts.
- `dnsfilter_get_total_domain_stats`, `dnsfilter_get_total_domains`, `dnsfilter_get_total_domains_organizations`, `dnsfilter_get_total_domains_users` - domain request totals.
- `dnsfilter_get_total_organizations_requests`, `dnsfilter_get_total_organizations_stats` - organization-level request totals.
- `dnsfilter_get_total_requests`, `dnsfilter_get_total_requests_agents`, `dnsfilter_get_total_requests_collections`, `dnsfilter_get_total_requests_geo`, `dnsfilter_get_total_requests_organizations`, `dnsfilter_get_total_requests_users` - total request-count totals, broken out by dimension.
- `dnsfilter_get_total_threats`, `dnsfilter_get_total_threats_organizations`, `dnsfilter_get_total_threats_users` - blocked-threat totals.

## Sensitivity

Every tool in this connector is classified `isAdmin: true` in the Conduit gateway (see `result-cache.ts`'s `VENDOR_TOOL_CONFIG` entry for this vendor), a whole-connector decision rather than a per-tool one. DNSFilter's surface here is a DNS security product: policy configuration, block-page branding, and - especially - the traffic-report family carry per-device/per-user DNS query history and threat-detection data (`dnsfilter_get_query_logs` returns individual domains queried by individual requesters; several `total_*`/`top_*` reports break results out by local user or client/agent). That's PII- and security-posture-adjacent data even as a plain read, the same posture this WYRE Conduit wave has taken for other security-category connectors (Cork, CyberQP, Cisco Duo).

## Development

```bash
npm install
npm run build
npm test
npm run lint   # tsc --noEmit
```

## Docker

```bash
docker build -t dnsfilter-mcp .
docker run -p 8080:8080 -e DNSFILTER_API_KEY=... dnsfilter-mcp
```

## License

Apache-2.0
