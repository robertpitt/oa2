# Releasing

This project uses [Changesets](https://github.com/changesets/changesets) for version management and publishing.

## How it works

All packages in this monorepo are versioned together using **synchronized versioning**. When you release, all packages will get the same version number, keeping everything in sync.

## Creating a changeset

When you make changes that should trigger a release, create a changeset:

```bash
yarn changeset
```

This will:
1. Ask which packages should be released
2. Ask what type of change this is (major, minor, patch)
3. Ask for a summary of the changes
4. Generate a changeset file in `.changeset/`

## Version types

- **Major (1.0.0 → 2.0.0)**: Breaking changes
- **Minor (1.0.0 → 1.1.0)**: New features, backwards compatible
- **Patch (1.0.0 → 1.0.1)**: Bug fixes, backwards compatible

## Release process

### Manual release

```bash
# 1. Update versions and changelog
yarn changeset:version

# 2. Review the changes, then publish
yarn changeset:publish
```

### Automated release (Recommended)

1. Create a changeset for your changes:
   ```bash
   yarn changeset
   git add .
   git commit -m "feat: add new feature"
   git push
   ```

2. When merged to `main`, the GitHub Action will:
   - Create a "Release PR" with version bumps and changelog
   - When you merge the Release PR, it automatically publishes to npm

## Useful commands

```bash
# Check what would be released
yarn changeset:status

# Create a changeset
yarn changeset

# Apply changesets to update versions
yarn changeset:version

# Publish to npm
yarn changeset:publish

# Full release process (manual)
yarn release

# Preview release
yarn prerelease
```

## First time setup

1. Make sure you have an npm account and are logged in:
   ```bash
   npm login
   ```

2. Add npm token to GitHub secrets as `NPM_TOKEN`

3. Ensure your package.json has the correct:
   - `repository` field
   - `license` field
   - `access` is set to "public" in `.changeset/config.json`

## Example workflow

```bash
# Make your changes
git checkout -b feature/new-oauth-flow

# Edit code...
# ...

# Create a changeset
yarn changeset
# Select: @oa2/core (since it's the only publishable package)
# Select: minor (for new feature)
# Description: "Add new OAuth flow support"

# Commit everything
git add .
git commit -m "feat: add new OAuth flow support"
git push origin feature/new-oauth-flow

# Create PR, get it reviewed and merged
# The GitHub Action will create a Release PR
# Merge the Release PR to publish to npm
``` 