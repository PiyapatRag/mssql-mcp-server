# Contributing

Thanks for your interest in improving
[@piyapat/mssql-mcp-server](https://www.npmjs.com/package/@piyapat/mssql-mcp-server)!
Contributions are welcome for:

- Additional monitoring features
- Performance optimizations
- Bug fixes
- Documentation improvements

## Development Setup

```bash
git clone https://github.com/PiyapatRag/mssql-mcp-server
cd mssql-mcp-server
npm install
npm run build
```

### Scripts

| Command | Description |
| --- | --- |
| `npm run build` | Compile TypeScript to `build/`. |
| `npm run dev` | Compile in watch mode. |
| `npm start` | Run the compiled server. |

### Testing Locally

```bash
export MSSQL_SERVER=localhost
export MSSQL_DATABASE=testdb
export MSSQL_USER=sa
export MSSQL_PASSWORD=password

npm start
```

## Pull Requests

1. Fork the repo and create a feature branch.
2. Keep changes focused; match the existing code style.
3. Run `npm run build` and confirm it compiles cleanly.
4. Update `README.md` and `CHANGELOG.md` (under `## [Unreleased]`) when behavior changes.

## Releasing (Maintainers)

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
and [Keep a Changelog](https://keepachangelog.com/).

1. Move the `## [Unreleased]` entries in [CHANGELOG.md](CHANGELOG.md) under a new
   version heading and update the compare links.
2. Bump the version:
   ```bash
   npm version <patch|minor|major>
   ```
3. Build and publish (the `prepare` script builds automatically):
   ```bash
   npm login
   npm publish --access public
   ```
4. Push the tag:
   ```bash
   git push --follow-tags
   ```

Users can then run it with:

```bash
npx @piyapat/mssql-mcp-server
```
