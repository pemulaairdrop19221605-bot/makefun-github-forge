[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/pemulaairdrop19221605-bot/makefun-github-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/pemulaairdrop19221605-bot/makefun-github-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

# github-core-clone-01 forge

A standalone, GitHub-compatible git forge in one Node 22 process, standard library
only (`node:http`, `node:crypto`, `node:zlib`). No dependencies, no git binary, no
external service, no UI.

## Run it

```sh
node main.ts
```

`main.ts` is the kit starter's lifecycle, kept as-is: bind an ephemeral port,
`POST {port}` to `$MAKEFUN_ENV_URL/register`, poll `GET $MAKEFUN_ENV_URL/done`
until `{done: true}`, exit 0. The server itself is `app.ts` (`createApp()`).

## Surfaces

- **Git smart HTTP** `/{owner}/{repo}.git`: upload-pack protocol v2
  (`ls-refs`, `fetch` with `shallow`/`deepen`, thin packs, side-band-64k) and
  receive-pack v0 (`report-status`, `side-band-64k`, `delete-refs`).
  Fast-forward only; a non-fast-forward push is refused per ref with
  `ng <ref> non-fast-forward` and the ref does not move. Packs are plain
  objects (no deltas) with a SHA-1 trailer; incoming packs resolve OFS/REF
  deltas and verify every object hash.
- **REST v3** `/api/v3`: repositories, branches, commits, contents, labels,
  issues, comments, pull requests, files and squash merges. Every reply is
  `application/json` with a non-empty `X-GitHub-Request-Id`; unknown routes
  are JSON 404s, malformed bodies JSON 400s. `Bearer $MAKEFUN_SHOP_TOKEN`
  required; a missing or wrong token is 401. A repository name under another
  owner is 404, never 403.
- **GraphQL v4** `/api/graphql`: a small parser and executor for the documents
  `gh` and `github-mcp-server` send — `viewer`, `repository` (fields,
  `issues`/`pullRequests` connections with cursor pagination, `issue`,
  `pullRequest`), `node(id:)` with opaque Relay ids, `__type` introspection
  for `Issue`/`PullRequest`/`Repository`/`SearchType`, the `createIssue`,
  `closeIssue`, `createPullRequest`, `mergePullRequest` and `addComment`
  mutations, and batched operation arrays. Unknown fields answer HTTP 200
  with an `errors` array.
- **MCP** `/mcp`: JSON-RPC 2.0 Streamable HTTP, modern revision `2026-07-28`
  (`server/discover` with `supportedVersions`, plus the legacy `initialize`
  handshake). Six tools — `create_repo`, `get_repo`, `create_issue`,
  `list_issues`, `create_pull_request`, `merge_pull_request` — acting on the
  same store as REST. Unknown tools answer -32602, missing arguments answer
  `isError: true`, a non-JSON body answers HTTP 400 with -32700, no
  `Authorization` answers 401.

## Design notes

- One deterministic in-memory store shared by all four surfaces. No clock
  and no randomness in any served byte: commit timestamps, `created_at` /
  `merged_at` and global ids derive from fixed values or insertion order, so
  two runs of the same trial export byte-identical state.
- The suite never tells the entry the token owner's login, so the forge
  learns it: the first owner-bearing request for a repository binds that
  repository (and the viewer login) to the owner it names. The suite always
  reads a repository under its true owner before trying another owner.
- Performance: per-issue serialized JSON is cached (invalidated per issue on
  write); fetch packs are cached per (wants, haves, depth, shallow) and
  invalidated per repository on any ref change, so 50 concurrent shallow
  clones of one tip serve the same bytes; pushes validate SHA-1 only and
  check fast-forward through a commit-graph index.
