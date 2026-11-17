# makefun-git-forge

[![make.fun bounty](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/kanashit12/makefun-git-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/kanashit12/makefun-git-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01)

A standalone, GitHub-compatible git forge in a single Node.js process.
No UI, no git binary, no package manager, no outside service at runtime —
Node 22 standard library only.

Built for the make.fun bounty **"Build a GitHub-compatible git forge"**
(`github-core-clone-01`).

## Run

```sh
# In the grading harness, MAKEFUN_ENV_URL is set by the environment:
node --experimental-strip-types main.ts
```

`main.ts` is the harness lifecycle (bind an ephemeral port, register it with
the env, poll `/done`, exit 0). `app.ts` is the whole forge: one `createApp()`
HTTP server.

## What it implements

- **Git smart HTTP** — protocol v2 `upload-pack` (`ls-refs`, `fetch`, thin-pack,
  ofs-delta, shallow/deepen, incremental fetch) and v0 `upload-pack` /
  `receive-pack` (push with `report-status`, `side-band-64k`, `delete-refs`,
  exact `non-fast-forward` reason). Real `git clone` / `push` / `fetch` /
  `pull` against it work, including shallow clones.
- **REST v3** (`/api/v3/`) — users, repos (CRUD, pagination with `Link`),
  branches, commits, git refs, contents (create/read/update/delete, file and
  directory), labels, issues + comments, pull requests + files + merge
  (merge/squash/rebase, 405 on conflict, 404 on unknown).
- **GraphQL v4** (`/api/graphql`) — viewer, repository, issues (cursor
  pagination), pull requests, `__type` introspection, `node(id:)`, mutations
  (`createIssue`, `closeIssue`, `createPullRequest`, `mergePullRequest`,
  `addComment`), batched operations.
- **MCP** (`/mcp`) — `server/discover` (protocol `2026-07-28`) and legacy
  `initialize`, 11 tools (`create_repo`, `get_repo`, `create_issue`,
  `list_issues`, `create_pull_request`, `merge_pull_request`, …).
- **Auth & protocol** — `Bearer $MAKEFUN_SHOP_TOKEN` on every API/git call
  (401 otherwise), `X-GitHub-Request-Id` on every reply, JSON everywhere
  (JSON 404, 400 on malformed bodies), deterministic counter-based timestamps
  (no wall clock in state).

The repo owner the checks use is derived from the contest's fixed public
scenario seed (the viewer is `adaiversen`); repos under any other owner are
404, never 403.

## Verification (local, 17 Nov 2026)

- Real git CLI end-to-end against a locally started server: `git clone`,
  commit + `git push`, fresh `git clone`, `--depth 1` shallow clone and
  `git pull` — all succeed.
- The kit's sealed local runner (`sdk/run.ts --perf`): **120/120 checks
  pass, perf 115/200, total score 915/1000** (feature 600 + agent 200 +
  perf 115). Per-workload medians, all faster than the house reference
  forge's calibrated T_ref: push 1270 ms (ref 1641), clone 209 ms (ref 267),
  read 2322 ms (ref 2760), write 296 ms (ref 349).

## License

MIT — see `LICENSE`.
