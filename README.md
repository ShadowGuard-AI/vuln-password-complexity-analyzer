# vuln-Password-Complexity-Analyzer
Analyzes password policies on web applications to identify weak requirements and potential vulnerabilities related to password management. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

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
- `--submit_xpath`: XPath to the submit button.
- `--success_regex`: Regex to match for successful login.
- `--failure_regex`: Regex to match for failed login.
- `--test_passwords`: List of passwords to test. Defaults to a pre-defined list of common weak passwords.

## License
Copyright (c) ShadowGuardAI
