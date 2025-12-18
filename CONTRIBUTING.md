# Contributing to mcp-guard

Thank you for your interest in contributing to mcp-guard! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/greg-py/mcp-guard.git
   cd mcp-guard
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Build the project**
   ```bash
   npm run build
   ```

4. **Run tests**
   ```bash
   npm test
   ```

## Development Workflow

### Making Changes

1. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes in the `src/` directory

3. Add tests for new functionality in `test/`

4. Ensure all tests pass:
   ```bash
   npm test
   ```

5. Ensure the build succeeds:
   ```bash
   npm run build
   ```

### Code Style

- **TypeScript**: We use strict TypeScript with all strict flags enabled
- **ESM**: This is an ESM-only package
- **Functional patterns**: Prefer pure functions and composition for guards
- **Documentation**: Add JSDoc comments to all public APIs

### Testing

We use [Vitest](https://vitest.dev/) for testing. Tests should:

- Cover both success and failure cases
- Include edge cases and security scenarios
- Mock external dependencies (LLM providers, approval handlers)
- Be fast and deterministic

Run tests with coverage:
```bash
npm run test:coverage
```

## Pull Request Process

1. **Update documentation** — If your change affects the public API, update the README
2. **Add tests** — All new features must have corresponding tests
3. **Pass CI** — Ensure build and tests pass locally before submitting
4. **Write clear commit messages** — Use conventional commit format when possible

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(guards): add rate limiting guard`
- `fix(validation): handle nested arrays correctly`
- `docs: update README with new examples`

## Reporting Issues

When reporting bugs, please include:

1. **Version** of mcp-guard you're using
2. **Node.js version**
3. **Steps to reproduce** the issue
4. **Expected behavior** vs **actual behavior**
5. **Minimal code example** if applicable

## Security Vulnerabilities

If you discover a security vulnerability, please **do not** open a public issue. Instead, email the maintainers directly with details about the vulnerability.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Accept constructive criticism gracefully
- Focus on what is best for the community

## License

By contributing to mcp-guard, you agree that your contributions will be licensed under the MIT License.
