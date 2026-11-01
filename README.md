# vuln-Password-Complexity-Analyzer
Tests whether supplied passwords are accepted for a supplied username at a supplied login URL, and reports which ones the site accepted. This tests whether those passwords are valid credentials for that one account. It does not analyze a site's password policy: it makes no registration or password change request and runs no length or character class test, because policy requirements are set when a password is created or changed. Tested passwords are reported by index and a short hash prefix only, never in clear, in the logs, the printed results, or any file.

## Install
`git clone https://github.com/ShadowGuardAI/vuln-password-complexity-analyzer`

## Usage
`./vuln-password-complexity-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--url`: URL of the login page.
- `--username`: Username to use for testing.
- `--username_field`: Name of the username field in the login form.
- `--password_field`: Name of the password field in the login form.
- `--success_regex`: Regex to match for successful login. At least one of `--success_regex` or `--failure_regex` must be set, and a run where every request failed or every result is inconclusive exits non-zero.
- `--failure_regex`: Regex to match for failed login.
- `--test_passwords`: List of passwords to test. Defaults to a pre-defined list of common weak passwords.

## License
Copyright (c) ShadowGuardAI
