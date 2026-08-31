# svc-okta-identity-mcp

An MCP server that exposes read-only Okta identity lookups to an AI client, so an admin can ask about a user, or compare several, without leaving the conversation.

Design and governance decisions, including what was declined and why, can be found at [docs/decisions.md](docs/decisions.md)

A companion project, [svc-okta-log-triage](https://github.com/austinhalldev/svc-okta-log-triage), governed what data may cross a boundary, pseudonymizing identities before they reached an external model. This one governs a different question: what an agent is permitted to do.

## The problem

An admin fielding access review questions, things like "was this person offboarded and when" or "does this person's access match their team," answers them by clicking through the Okta console, one user at a time.

For a single lookup, that's fine. The console is faster than any tool call for checking if one person is still active, and it's authoritative.

Comparisons are where it breaks down. Checking access across several people means a stack of open tabs or a spreadsheet export, lined up by hand. In practice, the comparison gets skipped.

## What it does

An MCP server exposing three read-only Okta identity tools to an AI client. It authenticates to Okta as a scoped service app, builds every tool response from an explicit per-tool field allowlist, and returns Okta's own values without interpretation.

## Intended user

An Okta admin who fields identity and access-review questions from HR and managers. The requester is never the operator. An admin runs the tool and relays the answer.

## The tools

All three tools return the same identity core plus whatever that tool adds: `id`, `status`, `login`, `email`, `firstName`, `lastName`. `status` comes back raw, `ACTIVE`, `DEPROVISIONED`, `SUSPENDED`, `STAGED`, and so on, rather than translated into something friendlier. The audience already knows this vocabulary from the console, and a translated version would drift out of sync with it over time.

### lookup_user

Core fields plus `statusChanged`, the timestamp of the user's last status transition.

### lookup_user_org_context

Core fields plus `department`, `manager`, `title`. These three come back `null` when Okta has nothing set for them, they're never omitted, so "not set in Okta" and "this tool doesn't return that field" stay distinguishable.

### compare_user_groups

Core fields plus `groups` (each `id`, `name`, `description`, `type`), for up to 5 users in a single call. Above 5 it refuses outright rather than silently comparing fewer than asked. It returns each user's raw data side by side; it doesn't compute an intersection or a common/unique summary. The comparison is the model's job, and the raw output is there so it can be checked against the source.

## Field allowlisting

This is the control the rest of the project is built around.

Every tool response is built by explicitly selecting named fields into a new object. None of them start from the Okta response and delete keys. The allowlists live in `identity_fields.py`, one function per tool, and that file is the entire exposure surface: read it once and you know exactly what any tool can return. A new attribute Okta adds to a user's profile tomorrow doesn't show up in any tool's output until someone edits that file.

The reason is where a tool result goes next. It doesn't stay in this server. Every tool result enters the conversation, which means it goes to whatever model provider the client is using. Returning a whole Okta user object would ship every profile attribute the org stores, employee ID, phone number, manager, and any custom attributes the org has added, regardless of what was actually asked for. Selecting fields in makes that a deliberate choice instead of an accident. Deleting fields out means the default is disclosure, and the exposure grows every time Okta or the org adds a new attribute, with nobody deciding that it should.

## Authentication

The server authenticates as an Okta API Services app with OAuth 2.0 and a private key, not SSWS. An SSWS token is a static credential that inherits the permissions of whoever created it, so an SSWS token minted by a super admin is effectively a super admin credential sitting in an env file, with no way to scope it down after the fact. An API Services app is scoped on its own terms, independent of who set it up.

Scope and role are both required, and neither is enough alone. The app requests `okta.users.read` and `okta.groups.read` as scopes. Those are meaningless without a role that grants actual reach into the tenant, so the app is also bound to a custom admin role with exactly two permissions, view users' profile attributes and view groups and their details, applied to a resource set covering all users and all groups. Grant the scope without the role and token creation still succeeds; every API call then comes back 403, which looks like a broken tool rather than a permissions gap.

Read-only here doesn't rest on scope choice alone. There's no write tool anywhere in this server. A client that ignored every scope restriction and every hint still couldn't call something that was never registered.

## Deployment

The server runs in a rootless Podman container. Credentials are mounted into it read-only at runtime and never baked into the image, and the port is published to `127.0.0.1` only. Starting and stopping the container is the actual on/off switch for the agent's reach into the tenant: stopped, there's no live credential and no path in.

Claude Desktop can't talk to the container directly. Its local MCP config only knows how to launch a process over stdio, so reaching an HTTP server running in a container needs `mcp-remote`, a stdio-to-HTTP proxy that Claude Desktop launches on the host. See entry 10 of the decisions journal for what that costs and why the container decision still holds anyway.

## Setup

### Prerequisites

- Python 3.12 (only needed to run `server.py` directly on the host; the container image supplies its own)
- Podman, for building and running the runtime container
- An Okta tenant where you can create an API Services app
- Node.js, for `npx`, which launches `mcp-remote`
- An MCP client. Built and tested against Claude Desktop, which needs `mcp-remote` as a stdio bridge (see below)

### Okta Configuration

1. Applications > Create App Integration > API Services. Name it `svc-okta-identity-mcp`.
1. On the **General** tab, set client authentication to **Public Key / Private Key** and generate a keypair. Save the private key, it's only shown once. Note the key ID (`kid`) shown in the public keys table that pops up.
1. On the **Okta API Scopes** tab, grant `okta.users.read` and `okta.groups.read`, nothing else.
1. Under **Security > Administrators > Roles**, create a custom role with exactly two permissions: **view users' profile attributes** and **view groups and their details**. Okta's wording for these shifts between console versions, so match on meaning rather than the exact string. The group permission was confirmed reading "View groups and their details" at the time of writing; the user one is close to, but may not exactly match, "view users' profile attributes".
1. Under **Security > Administrators > Resource Sets**, create a resource set covering all users and all groups.
1. On the app's **Admin roles** tab, assign the custom role, bound to that resource set.

Leave the org level "Public client app admins" setting disabled, so it doesn't skip role assignment.

### Local Configuration

Save the private key JWK as `private_key.json` in the project root, then copy `.env.example` to `.env` and fill in:

```
OKTA_ORG_URL=https://your-org.okta.com
OKTA_CLIENT_ID=your-client-id
OKTA_KEY_ID=your-key-id
OKTA_PRIVATE_KEY_PATH=private_key.json
```

`OKTA_ORG_URL` is the tenant hostname, not the `-admin` console host, and takes no trailing slash. `.env` and `private_key.json` are gitignored and must stay that way; neither should ever be added to the container image either, see Deployment above.

### Build and Run

```bash
podman build -t okta-identity-mcp:latest -f Containerfile .
```

```bash
podman run -d \
  --name okta-identity-mcp \
  --userns=keep-id \
  --user "$(id -u):$(id -g)" \
  -v "$(pwd)/.env:/app/.env:ro" \
  -v "$(pwd)/private_key.json:/app/private_key.json:ro" \
  -p 127.0.0.1:8000:8000 \
  okta-identity-mcp:latest
```

`--userns=keep-id` and `--user` together keep the process non-root while still able to read the two mounted files, which are owned by your own host user. Check it's up with `podman ps --filter name=okta-identity-mcp`, and stop it with `podman stop okta-identity-mcp`.

### Claude Desktop Configuration

Claude Desktop only launches stdio servers, so it reaches the container through `mcp-remote`, a proxy that speaks stdio to Claude Desktop and HTTP to the container. Add this to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "okta-identity": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:8000/mcp"]
    }
  }
}
```

The explicit `"type": "stdio"` is required; omitting it gets the entry silently skipped. See entry 10 of the decisions journal for how that was found and what it means for this project's threat model.

## Limitations

This is a working reference, not a production tool.

**Only tested against a small sandbox tenant** built for this project. A tenant with real headcount, nested groups, or heavier custom schemas will look nothing like what this was exercised against.

**The 5-user cap on `compare_user_groups` is a judgment call, not a calculation.** Users are the wrong unit for bounding egress. Five users in a light tenant might be twenty group records; in a heavy one it could be well over a hundred. A cap on total groups returned would bound egress more honestly, and isn't built.

**No pagination handling on group lists.** `fetch_user_groups` assumes Okta returns a user's full group list in one response, which holds for the tenant this was built and tested against. If Okta ever returns a `next` link, it fails loudly rather than silently returning a partial list, but it still can't fetch the rest.

**Tool annotations are hints, not enforcement.** `readOnlyHint` and the compare tool's docstring instructions to the model are both things a client or model could ignore. The actual read-only guarantee comes from scope and from no write tool existing to call, not from either of these.

**`mcp-remote` is unaudited third-party code.** It's fetched from npm by `npx` at launch and runs on the host as you, not in the container. It's widely used and it's a proxy, not a file tool, but it's still code this project didn't write or review, and the example above doesn't pin a version.

**For the simple case, the console is still faster.** Nothing here beats two clicks in the Okta console for "is this person still active." The value is in the comparisons the console makes tedious enough that they don't happen, not in any single lookup.
