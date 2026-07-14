# contributing

contributions are welcome — issues, fixes, and features.

## llm-generated contributions

using an llm (claude, codex, whatever) to write a change is fine and encouraged.
there is no penalty and no need to hide it, but everything will be manually
reviewed later.

- open a pr and describe what the change does and why, in your own words. if you
  can't explain it, it isn't ready.
- keep prs small and focused — one change per pr. large, sprawling, or
  auto-generated dumps that a human can't reasonably review will be closed.
- make sure it builds and the code is formatted (`go build ./...`, `go vet ./...`,
  `gofmt -w .`) before you open the pr.
- do not paste secrets, tokens, or real credentials into code, tests, or issues.

this is a project that handles other people's login credentials and encryption
keys, so security-sensitive changes (auth, oauth, token storage, the crypto in
`internal/store` / `internal/assets`) get extra scrutiny. explain the threat
model you had in mind.

## style

match the surrounding code: small focused functions, early returns, errors
handled first, no cleverness for its own sake. comments explain *why*, not *what*.

by opening a pr you confirm you have the right to contribute the code and are
okay with it being released under the project's license.
