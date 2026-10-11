# Commands
- Build/check: `cargo check --all-targets`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Test: `cargo nextest run` then `cargo test --doc`
- Supply chain (before PR): `cargo deny check`

# Conventions
- thiserror in libs, anyhow in bins; no unwrap/expect outside tests
- Every `unsafe` block has a `// SAFETY:` comment; run miri on crates with unsafe

# Git
- Never commit to main. Feature work happens in a worktree/branch `feat/<slug>`
- Conventional commits; each commit compiles and passes tests
- PRs: squash-merge after CI green and no open Critical/Important review findings
