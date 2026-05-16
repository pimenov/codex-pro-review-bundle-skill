# Security Policy

This project helps reduce accidental context leakage, but it is not a formal security boundary.

Always inspect generated bundles before pasting them into any external model or service.

## Reporting Safety Issues

Please do not post real secrets, tokens, private keys, client data, raw production logs, browser profiles, or personal data in public issues or pull requests.

If you find a bypass, false negative, or dangerous default:

- report it with synthetic examples whenever possible
- describe the expected and actual behavior
- include the command you ran
- avoid attaching real private material

Useful reports include secret-pattern misses, unsafe path inclusion, confusing warnings, and cases where the manifest marks a risky bundle as complete.
