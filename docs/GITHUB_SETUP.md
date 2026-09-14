# GitHub repository setup

Repository files define contribution policy and automated checks. The following safeguards live in GitHub settings and must be enabled once by an administrator.

## Repository ruleset

Create a ruleset targeting the default branch (`main`) with these protections:

- block branch deletion and force pushes;
- require changes through pull requests;
- require one approving review for outside contributions;
- dismiss approvals when the reviewed code changes;
- require all review conversations to be resolved;
- require the `backend` and `dashboard` CI jobs to pass;
- allow the maintainer to bypass the rules only for emergency recovery.

Enable merge commits, squash merging, or rebase merging according to the history style you intend to maintain. Squash merging is a simple default for outside contributions.

## Security settings

Enable these features under **Settings → Security**:

- private vulnerability reporting;
- dependency graph and Dependabot alerts;
- Dependabot security updates;
- secret scanning and push protection, when available for the repository.

The repository's [security policy](../.github/SECURITY.md) directs reporters to private vulnerability reporting, so enable that feature before announcing the policy.

## Repository profile

Set a short description, the public project website, and topics such as `dns`, `dns-server`, `privacy`, `self-hosted`, `rust`, `unbound`, and `ad-blocking`. Keep claims factual and avoid performance or security guarantees that are not backed by published tests.

Use GitHub Releases for stable versions. Each release should identify the commit, summarize user-visible changes, list configuration or migration steps, and attach checksums for any downloadable artifacts.
