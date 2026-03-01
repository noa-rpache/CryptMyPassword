# Contributing to CryptMyPassword

Thank you for your interest in contributing to CryptMyPassword! We welcome contributions from everyone, whether it's code, documentation, bug reports, or feature requests.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Commit Conventions](#commit-conventions)
- [Submitting Changes](#submitting-changes)
- [Pull Request Process](#pull-request-process)
- [Review Expectations](#review-expectations)
- [Getting Help](#getting-help)

## Code of Conduct

This project adheres to the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project authors.

## Getting Started

### Prerequisites

Before you start, ensure you have:
- Git installed and configured
- Docker
- A GitHub account

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/Pablodiz/CryptMyPassword.git
   cd CryptMyPassword
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/Pablodiz/CryptMyPassword.git
   ```

## Development Setup

### Backend

```bash
cd server
docker-compose up
# Services:
# - FastAPI: http://127.0.0.1:8000
```

### Extension Development

```bash
# No build step needed; the extension loads directly

# Firefox:
# 1. Go to about:debugging#/runtime/this-firefox
# 2. Click "Load Temporary Add-on"
# 3. Select browser/manifest.json

# Chrome:
# 1. Go to chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the browser/ folder
```

### Verify Setup

```bash
# Check API is running
curl http://127.0.0.1:8000/docs

# Load extension in browser and test
```

## Making Changes

### Create a Feature Branch

```bash
# Update main branch
git fetch upstream
git checkout develop

git checkout -b feature/your-feature-name
```

### Branch Naming Convention

- `feature/add-feature-name` - New features
- `fix/bug-description` - Bug fixes
- `docs/documentation-topic` - Documentation updates
- `refactor/code-area` - Code refactoring
- `test/test-description` - Test improvements
- `chore/maintenance-task` - Maintenance and chores

### Make Your Changes

- Keep changes in one area at a time
- Update documentation as needed
- Test your changes before committing

## Coding Standards

### Python Backend

We follow PEP 8 with these conventions:

```python
# Use type hints
def save_password(domain: str, user: str, password: str) -> dict:
    """Save a password securely."""
    pass

# Document functions and classes
class PasswordManager:
    """Manages password generation and storage."""
    
    def generate(self, length: int = 24) -> str:
        """Generate a cryptographically secure password."""
        pass

# Use meaningful variable names
user_email = "user@example.com"  # Good
ue = "user@example.com"  # Avoid
```

### JavaScript/Browser Extension

We follow ESLint recommended standards:

```javascript
// Use const by default, let if needed, avoid var
const api = "http://127.0.0.1:8000";
let counter = 0;

// Use async/await over .then()
async function loadPasswords() {
  const passwords = await sendMessageToBackground({
    type: "GET_ALL_PASSWORDS",
  });
  return passwords;
}

// Use meaningful variable names
const passwordField = document.querySelector('input[type="password"]');
const domainName = window.location.hostname;

// Use arrow functions for callbacks
array.forEach((item) => {
  console.log(item);
});
```

### Naming Conventions

- **Functions/Methods**: Use snake_case (Python), camelCase (JavaScript)
  - Python: `generate_password()` ✅
  - JavaScript: `generatePassword()` ✅

- **Constants**: Use UPPER_SNAKE_CASE
  - `MAX_PASSWORD_LENGTH = 128` ✅
  - `API_TIMEOUT = 5000` ✅

- **Classes**: Use PascalCase
  - `PasswordManager` ✅
  - `PasswordManager` ✅

### Code Comments

- Keep comments up-to-date with code
- Use clear, professional language
- Write them in english to keep a consistent style

## Commit Conventions

We follow Conventional Commits for clear, semantic commit messages:

```
[type]: description

[optional body]

[optional footer]
```

### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that don't affect code meaning (formatting, semicolons, etc.)
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **perf**: Code change that improves performance
- **test**: Adding or updating tests
- **chore**: Changes to build process, dependencies, tooling, etc.

### Examples

```
feat: add password encryption at rest

fix: prevent duplicate password saves on form submit

docs: update installation instructions

test: add tests for HIBP integration

refactor: simplify password endpoint routing

chore: update fastapi to 0.104.0
```

### Commit Message Template

```
feat: implement password strength meter

Add a new endpoint that analyzes password strength based on:
- Length requirements
- Character diversity
- Common patterns
- HIBP database

Fixes #123
```

## Submitting Changes

### Before Pushing

```bash
# Update your branch with latest upstream changes
git fetch upstream
git rebase upstream/main
```

### Push to Your Fork

```bash
git push origin feature/your-feature-name
```

## Pull Request Process

### Creating a Pull Request

1. Go to the original repository on GitHub
2. Click "New Pull Request"
3. Select `main` branch as base
4. Select your feature branch as compare
5. Fill in the PR template (provided by repository)

### PR Title and Description

**Title Format**:
```
[type] Short description (50 characters max)
```

**Examples**:
- `[feat] Add password strength meter`
- `[fix] Prevent duplicate saves on form submit`
- `[docs] Update installation guide`

**Description Template**:
```markdown
## Description
Brief description of what this PR does.

## Related Issues
Fixes #123
Related to #456

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
How to test these changes:
1. Step 1
2. Step 2
3. Step 3

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Changes reviewed locally
- [ ] Commit messages follow conventions
```

## Review Expectations

### Code Review Guidelines

Reviewers will check:
- ✅ Code quality and style consistency
- ✅ Documentation is clear and accurate
- ✅ No security vulnerabilities introduced
- ✅ Performance impact is acceptable
- ✅ Commit messages follow conventions
- ✅ Branch is up-to-date with main
- ✅ No merge conflicts

### What to Expect

- Timelines may vary because this is not actively mantained.
- Once reviewed, your PR will be merged or feedback will be provided.

### Addressing Feedback

```bash
# Make requested changes
git add .
git commit
git push origin feature/your-feature-name
```

## Handling Conflicts

If your PR has merge conflicts, merge the latest main into your branch before pushing.

## Getting Help

### Questions or Need Guidance?

- Check [README.md](README.md) and [docs/](docs/) for documentation
- Open a discussion in GitHub Discussions
- Check existing issues to see if your question is answered
- Email: [dev@cryptmypassword.dev](mailto:dev@cryptmypassword.dev)

### Useful Resources

- [Git Documentation](https://git-scm.com/doc)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [PEP 8 Style Guide](https://pep8.org/)
- [MDN Web Docs](https://developer.mozilla.org/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes - For significant contributions
