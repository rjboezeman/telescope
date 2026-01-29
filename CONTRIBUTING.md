# Contributing to Telescope

Thank you for your interest in contributing to Telescope! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

## How to Contribute

### Reporting Bugs

If you find a bug, please open a GitHub Issue with:

- A clear, descriptive title
- Steps to reproduce the problem
- Expected vs actual behavior
- Your environment (Go version, Kubernetes version, Cilium version)
- Relevant log output (redact any sensitive information)

### Suggesting Features

Feature requests are welcome! Please open an Issue describing:

- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main` (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests and linting (see below)
5. Commit with a clear message
6. Push to your fork and open a Pull Request

#### Branch Naming

- `feature/description` for new features
- `fix/description` for bug fixes
- `docs/description` for documentation changes

#### Commit Messages

Write clear, concise commit messages:

```
Short summary (50 chars or less)

Optional longer description if needed. Explain what and why,
not how (the code shows how).
```

## Development Setup

### Prerequisites

- Go 1.21 or later
- Access to a Kubernetes cluster with Cilium (for integration testing)
- Docker (for building container images)

### Building

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/telescope.git
cd telescope

# Build
go build -o telescope .
```

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -v -cover ./...
```

### Code Quality

Before submitting a PR, ensure your code passes all checks:

```bash
# Format code
go fmt ./...

# Run linter
go vet ./...

# Optional: run staticcheck if installed
staticcheck ./...
```

### Local Testing

You can test against a local Kubernetes cluster with Cilium:

```bash
# Run telescope locally (requires access to Hubble Relay)
./telescope --hubble-endpoint=localhost:4245 --tls=false
```

For port-forwarding to Hubble Relay:

```bash
kubectl port-forward -n kube-system svc/hubble-relay 4245:80
```

## Pull Request Process

1. Ensure all tests pass and code is formatted
2. Update documentation if you're changing behavior
3. Add tests for new functionality
4. Keep PRs focused — one feature or fix per PR
5. A maintainer will review your PR and may request changes
6. Once approved, a maintainer will merge your PR

## Style Guidelines

- Follow standard Go conventions and idioms
- Use `gofmt` for formatting (this is non-negotiable)
- Keep functions focused and reasonably sized
- Add comments for exported functions and non-obvious logic
- Error messages should be lowercase and not end with punctuation

## Questions?

If you have questions about contributing, feel free to open an Issue with the `question` label.
