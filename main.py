#!/usr/bin/env python3
import argparse
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
DEFAULT_SUBMIT_BUTTON_XPATH = ""
DEFAULT_SUCCESS_REGEX = ""
DEFAULT_FAILURE_REGEX = ""
DEFAULT_TEST_PASSWORDS = ["Password123!", "WeakPassword", "123456", "password", "P@sswOrd"]


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes password policies on web applications.")
    parser.add_argument("--url", type=str, help="URL of the login page.", required=False, default=DEFAULT_URL)
    parser.add_argument("--username", type=str, help="Username to use for testing.", required=False)
    parser.add_argument("--username_field", type=str, help="Name of the username field in the login form.", required=False, default=DEFAULT_USERNAME_FIELD)
    parser.add_argument("--password_field", type=str, help="Name of the password field in the login form.", required=False, default=DEFAULT_PASSWORD_FIELD)
    parser.add_argument("--submit_xpath", type=str, help="XPath to the submit button.", required=False, default=DEFAULT_SUBMIT_BUTTON_XPATH)
    parser.add_argument("--success_regex", type=str, help="Regex to match for successful login.", required=False, default=DEFAULT_SUCCESS_REGEX)
    parser.add_argument("--failure_regex", type=str, help="Regex to match for failed login.", required=False, default=DEFAULT_FAILURE_REGEX)
    parser.add_argument("--test_passwords", nargs='+', type=str, help="List of passwords to test. Defaults to a pre-defined list of common weak passwords.", required=False, default=DEFAULT_TEST_PASSWORDS)

    return parser.parse_args()


def test_password_complexity(url, username, username_field, password_field, submit_xpath, success_regex, failure_regex, test_passwords):
    """
    Tests password complexity by attempting login with various passwords.

    Args:
        url (str): The URL of the login page.
        username (str): The username to use for testing.
        username_field (str): The name of the username field in the login form.
        password_field (str): The name of the password field in the login form.
        submit_xpath (str): The XPath to the submit button (currently unused).
        success_regex (str): The regex to match for a successful login.
        failure_regex (str): The regex to match for a failed login.
        test_passwords (list): A list of passwords to test.

    Returns:
        dict: A dictionary containing the results of the password complexity analysis.
    """
    results = {}
    try:
        for password in test_passwords:
            data = {username_field: username, password_field: password}
            try:
                response = requests.post(url, data=data)
                response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

                if success_regex and re.search(success_regex, response.text):
                    results[password] = "Login Successful (Unexpected)"
                    logging.warning(f"Password '{password}' successfully logged in, indicating a weak password policy.")
                elif failure_regex and re.search(failure_regex, response.text):
                    results[password] = "Login Failed (Expected)"
                    logging.info(f"Password '{password}' failed to login, which is expected.")
                else:
                    results[password] = "Inconclusive: Could not determine login status."
                    logging.warning(f"Could not determine login status for password '{password}'. Please check the success and failure regex.")

            except requests.exceptions.RequestException as e:
                logging.error(f"Request failed for password '{password}': {e}")
                results[password] = f"Request Failed: {e}"
            except Exception as e:
                logging.error(f"An unexpected error occurred while testing password '{password}': {e}")
                results[password] = f"Error: {e}"

    except Exception as e:
        logging.error(f"An error occurred during password complexity testing: {e}")
        return {"error": str(e)}

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

    # Additional validations can be added here (e.g., URL format validation)

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
            args.submit_xpath,
            args.success_regex,
            args.failure_regex,
            args.test_passwords
        )

        print("Password Complexity Analysis Results:")
        for password, result in results.items():
            print(f"- Password: '{password}', Result: {result}")

    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}", exc_info=True)  # Log the full traceback
        sys.exit(1)


if __name__ == "__main__":
    main()