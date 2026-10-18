# Security policy

## Reporting a vulnerability or a new variant

Please use GitHub's private vulnerability reporting: the **Security** tab, then
**Report a vulnerability**. Do not open a public issue for a bypass.

When reporting a new variant, include:
- the file names and paths involved
- a short description of how it runs (task, config file, build step)
- hashes of the malicious files

Do not attach live payloads. If a sample is needed, we will arrange a safe way
to share it.

## Scope

fontguard reads files, moves matches into its own quarantine folder, and blocks
git operations. It never deletes files unless you ask it to from the app, and it
never sends data anywhere.
