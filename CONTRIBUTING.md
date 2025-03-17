# Contributing to Voxco Server Monitoring Dashboard

Thank you for considering contributing to the Voxco Server Monitoring Dashboard! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and considerate of others.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with the following information:

1. A clear, descriptive title
2. Steps to reproduce the issue
3. Expected behavior
4. Actual behavior
5. Screenshots (if applicable)
6. Environment details (OS, browser, etc.)

### Suggesting Enhancements

If you have an idea for an enhancement, please create an issue with:

1. A clear, descriptive title
2. A detailed description of the proposed enhancement
3. Any relevant mockups or examples
4. Why this enhancement would be useful

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Run tests if available
5. Commit your changes (`git commit -m 'Add some feature'`)
6. Push to the branch (`git push origin feature/your-feature-name`)
7. Open a Pull Request

## Development Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   pip install -r requirements.txt
   ```
3. Copy the environment template:
   ```bash
   cp .env.template .env
   ```
4. Edit the `.env` file with your configuration
5. Start the development servers:
   ```bash
   ./start.sh
   ```

## Coding Standards

### JavaScript/React

- Use ES6+ features
- Follow consistent indentation (2 spaces)
- Use meaningful variable and function names
- Add comments for complex logic
- Use JSDoc for function documentation

### Python

- Follow PEP 8 style guide
- Use meaningful variable and function names
- Add docstrings for functions and classes
- Keep functions focused on a single responsibility

## Testing

- Add tests for new features when possible
- Ensure all tests pass before submitting a pull request
- Document any manual testing procedures

## Documentation

- Update documentation for any changes to APIs or functionality
- Use clear, concise language
- Include examples where appropriate

## Versioning

We use [Semantic Versioning](https://semver.org/) for this project:

- MAJOR version for incompatible API changes
- MINOR version for backwards-compatible functionality additions
- PATCH version for backwards-compatible bug fixes

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).