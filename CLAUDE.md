# Kryptor
Kryptor is an easy to use file hash generator written in Rust. Supports usage through the CLI or a dedicated GUI.

## Commands
- Check: `cargo check --all-targets`
- Format: `cargo fmt --all`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Test: `cargo nextest run --all-features` then `cargo test --doc` (nextest skips doctests) then `cargo miri test`
- Single test: `cargo nextest run <test_name>`
- Before opening a PR: `cargo deny check`
- Shell is Git Bash on Windows: use bash syntax and forward slashes, not PowerShell

## Code rules
- Errors: `thiserror` in library code, `anyhow` only in binaries
- No `unwrap()` / `expect()` / `panic!` outside tests; propagate with `?`
- Avoid `unsafe`; if unavoidable, every block needs a `// SAFETY:` comment
- Public items get doc comments, with a doctest example where useful
- Ask before adding a dependency; prefer std and existing deps
- Fix clippy warnings properly; `#[allow(...)]` only with a comment explaining why

## Security
- Never implement crypto primitives yourself; use audited crates (RustCrypto etc.)
- Keep secrets in `zeroize` / `secrecy` types; never log, print or `Debug` them
- Compare secrets and MACs in constant time (`subtle`)
- Keys and nonces come from OS CSPRNG (`getrandom` / `OsRng`); never reuse a nonce

## Git
- `main` is protected: never commit or push to it directly
- Branch names: `feat/<slug>`, `fix/<slug>`, `chore/<slug>`
- Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`); each commit compiles and passes tests
- Finish a branch by opening a PR (`/commit-push-pr`), never by merging locally
- Never force-push, rewrite pushed history, or use `--no-verify`
- Don't edit `.github/workflows/`, `.claude/` or `deny.toml` unless asked

## Reviews
- Check each finding against the code before changing anything; push back with reasoning if it's wrong
- Fix Critical/Important findings with a regression test
- Pre-existing or out-of-scope issues: list them for a separate issue, don't fix them in this PR
