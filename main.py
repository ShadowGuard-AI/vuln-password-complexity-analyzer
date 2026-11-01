#!/usr/bin/env python3
import argparse
import hashlib
import logging
import re
import requests
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default values
DEFAULT_URL = ""
DEFAULT_USERNAME_FIELD = "username"
DEFAULT_PASSWORD_FIELD = "password"
DEFAULT_SUCCESS_REGEX = ""
DEFAULT_FAILURE_REGEX = ""
DEFAULT_TEST_PASSWORDS = ["Password123!", "WeakPassword", "123456", "password", "P@sswOrd"]


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Tests supplied passwords against a login URL for a supplied username and reports which ones the site accepted. Passwords are reported by index and hash prefix only, never in clear.")
    parser.add_argument("--url", type=str, help="URL of the login page.", required=False, default=DEFAULT_URL)
    parser.add_argument("--username", type=str, help="Username to use for testing.", required=False)
    parser.add_argument("--username_field", type=str, help="Name of the username field in the login form.", required=False, default=DEFAULT_USERNAME_FIELD)
    parser.add_argument("--password_field", type=str, help="Name of the password field in the login form.", required=False, default=DEFAULT_PASSWORD_FIELD)
    parser.add_argument("--success_regex", type=str, help="Regex to match for successful login.", required=False, default=DEFAULT_SUCCESS_REGEX)
    parser.add_argument("--failure_regex", type=str, help="Regex to match for failed login.", required=False, default=DEFAULT_FAILURE_REGEX)
    parser.add_argument("--test_passwords", nargs='+', type=str, help="List of passwords to test. Defaults to a pre-defined list of common weak passwords.", required=False, default=DEFAULT_TEST_PASSWORDS)

    return parser.parse_args()


def password_label(index, password):
    """Identify a test password by index and a short hash prefix only, never in clear."""
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()[:8]
    return f"password[{index}] sha256:{digest}"


def test_password_complexity(url, username, username_field, password_field, success_regex, failure_regex, test_passwords):
    """
    Tests whether each supplied password is accepted for the supplied
    username at the supplied login URL. This attempts logins with ready
    made passwords for one existing account; it does not measure the
    site's password policy, which is set when a password is created or
    changed.

    Args:
        url (str): The URL of the login page.
        username (str): The username to use for testing.
        username_field (str): The name of the username field in the login form.
        password_field (str): The name of the password field in the login form.
        success_regex (str): The regex to match for a successful login.
        failure_regex (str): The regex to match for a failed login.
        test_passwords (list): A list of passwords to test.

    Returns:
        dict: Results keyed by password label (index and hash prefix),
        never by the password value itself.
    """
    results = {}
    for index, password in enumerate(test_passwords):
        label = password_label(index, password)
        data = {username_field: username, password_field: password}
        try:
            response = requests.post(url, data=data, timeout=10)
            # Classify the body against both regexes before any status
            # check, and record the status code with the result. A login
            # endpoint that answers a bad password with 401 is reporting
            # a login failure, not a request failure.
            status = response.status_code
            if success_regex and re.search(success_regex, response.text):
                results[label] = f"Login Successful (Unexpected) [HTTP {status}]"
                logging.warning(f"{label} successfully logged in for the supplied username.")
            elif failure_regex and re.search(failure_regex, response.text):
                results[label] = f"Login Failed (Expected) [HTTP {status}]"
                logging.info(f"{label} failed to login, which is expected.")
            else:
                results[label] = f"Inconclusive: Could not determine login status. [HTTP {status}]"
                logging.warning(f"Could not determine login status for {label}. Please check the success and failure regex.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for {label}: {e}")
            results[label] = f"Request Failed: {e}"
        except Exception as e:
            logging.error(f"An unexpected error occurred while testing {label}: {e}")
            results[label] = f"Error: {e}"
    return results


def validate_arguments(args):
    """
    Validates the command-line arguments.

    Args:
        args (argparse.Namespace): The parsed command-line arguments.

    Returns:
        bool: True if the arguments are valid, False otherwise.
    """
    if not args.url:
        logging.error("URL is required.")
        return False
    if not args.username:
        logging.error("Username is required.")
        return False
    if not args.success_regex and not args.failure_regex:
        logging.error("At least one of --success_regex or --failure_regex must be set; with neither set, no response can be classified.")
        return False

    return True


def main():
    """
    Main function to execute the password complexity analyzer.
    """
    try:
        args = setup_argparse()

        if not validate_arguments(args):
            sys.exit(1)  # Exit with an error code

        results = test_password_complexity(
            args.url,
            args.username,
            args.username_field,
            args.password_field,
            args.success_regex,
            args.failure_regex,
            args.test_passwords
        )

        print("Password Login Test Results:")
        for label, result in results.items():
            print(f"- {label}, Result: {result}")

        if not results:
            logging.error("No passwords were tested.")
            sys.exit(1)
        values = list(results.values())
        if all(v.startswith("Request Failed") or v.startswith("Error") for v in values):
            logging.error("Every test request failed; exiting non-zero.")
            sys.exit(1)
        if all(v.startswith("Inconclusive") for v in values):
            logging.error("Every result is inconclusive; the run determined nothing and exits non-zero.")
            sys.exit(1)

    except SystemExit:
        raise
    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}", exc_info=True)  # Log the full traceback
        sys.exit(1)


if __name__ == "__main__":
    main()