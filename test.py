import requests
import json
import time
import os

# ###############################################################
# # Configuration - REPLACE WITH YOUR ACTUAL VALUES           #
# ###############################################################
PROXY_URL = "https://localhost"
ADMIN_SECRET_KEY = "admin-secret-for-subscription-manager"  # <--- REPLACE THIS WITH YOUR ACTUAL ADMIN SECRET KEY!
TEST_USER_IDENTIFIER = "automated_test_user@example.com"

# Global variable to store the generated API key
GENERATED_API_KEY = None

# ###############################################################
# # Helper Functions                                          #
# ###############################################################

def print_section_header(title):
    """Prints a formatted section header."""
    print(f"\n###############################################################")
    print(f"# {title.ljust(59)} #")
    print(f"###############################################################\n")

def make_request(method, url, headers=None, data=None, params=None, cookies=None, allow_redirects=True):
    """Makes an HTTP request and prints relevant info."""
    print(f"Requesting: {method.upper()} {url}")
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            json=data,  # Use json=data for JSON bodies
            params=params,
            cookies=cookies,
            verify=False,  # Disable SSL certificate verification for self-signed certs
            allow_redirects=allow_redirects
        )
        print(f"Status Code: {response.status_code}")
        try:
            print(f"Response Body: {json.dumps(response.json(), indent=2)}")
        except json.JSONDecodeError:
            print(f"Response Body: {response.text[:500]}...") # Print first 500 chars if not JSON
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def pause_script():
    """Pauses the script execution."""
    input("\nPress Enter to continue...\n")

# ###############################################################
# # Test Steps                                                #
# ###############################################################

def test_generate_api_key():
    """Test 1: Generate a New API Key (Admin API)."""
    global GENERATED_API_KEY
    print_section_header("Test 1: Generate a New API Key (Admin API)")

    headers = {
        "Content-Type": "application/json",
        "X-Admin-Secret": ADMIN_SECRET_KEY
    }
    data = {
        "userIdentifier": TEST_USER_IDENTIFIER,
        "subscriptionStatus": "active"
    }

    response = make_request("POST", f"{PROXY_URL}/api/generate-token", headers=headers, data=data)

    if response and response.status_code == 200:
        try:
            response_json = response.json()
            if "apiKey" in response_json:
                GENERATED_API_KEY = response_json["apiKey"]
                print(f"Generated API Key: {GENERATED_API_KEY}")
            else:
                print("ERROR: 'apiKey' not found in response.")
        except json.JSONDecodeError:
            print("ERROR: Response is not valid JSON.")
    else:
        print("ERROR: Failed to generate API Key. Check Node.js proxy logs and MySQL connection.")
    pause_script()

def test_unauthorized_access():
    """Test 2: User Access - Unauthorized (No API Key)."""
    print_section_header("Test 2: User Access - Unauthorized (No API Key)")
    response = make_request("GET", f"{PROXY_URL}/")
    if response and response.status_code == 401:
        print("SUCCESS: Received 401 Unauthorized as expected.")
    else:
        print(f"FAILURE: Expected 401 Unauthorized, but got {response.status_code if response else 'no response'}.")
    pause_script()

def test_reauthorize_user():
    """Test 2.5: Reauthorize User to Active Subscription (Admin API)."""
    print_section_header("Test 2.5: Reauthorize User to Active Subscription (Admin API)")
    headers = {
        "Content-Type": "application/json",
        "X-Admin-Secret": ADMIN_SECRET_KEY
    }
    data = {
        "userIdentifier": TEST_USER_IDENTIFIER,
        "subscriptionStatus": "active"
    }
    response = make_request("POST", f"{PROXY_URL}/api/update-subscription-status", headers=headers, data=data)
    if response and response.status_code == 200:
        print("SUCCESS: User subscription status updated to 'active'.")
    else:
        print(f"FAILURE: Could not reauthorize user. Status: {response.status_code if response else 'no response'}.")
    pause_script()

def test_authorized_access_header():
    """Test 3: User Access - Authorized (API Key in Header)."""
    print_section_header("Test 3: User Access - Authorized (API Key in Header)")
    if not GENERATED_API_KEY:
        print("Skipping: API Key not generated. Run Test 1 first.")
        pause_script()
        return

    headers = {
        "Authorization": f"Bearer {GENERATED_API_KEY}"
    }
    response = make_request("GET", f"{PROXY_URL}/", headers=headers)
    if response and response.status_code == 200:
        print("SUCCESS: Received 200 OK with Authorization header as expected.")
    else:
        print(f"FAILURE: Expected 200 OK, but got {response.status_code if response else 'no response'}.")
    pause_script()

def test_authorized_access_query():
    """Test 4: User Access - Authorized (API Key in Query Parameter)."""
    print_section_header("Test 4: User Access - Authorized (API Key in Query Parameter)")
    if not GENERATED_API_KEY:
        print("Skipping: API Key not generated. Run Test 1 first.")
        pause_script()
        return

    params = {"apiKey": GENERATED_API_KEY}
    response = make_request("GET", f"{PROXY_URL}/", params=params)
    if response and response.status_code == 200:
        print("SUCCESS: Received 200 OK with API Key in query as expected.")
    else:
        print(f"FAILURE: Expected 200 OK, but got {response.status_code if response else 'no response'}.")
    pause_script()

def test_rate_limiting():
    """Test 5: Test Rate Limiting (105 requests in quick succession)."""
    print_section_header("Test 5: Test Rate Limiting (105 requests in quick succession)")
    if not GENERATED_API_KEY:
        print("Skipping: API Key not generated. Run Test 1 first.")
        pause_script()
        return

    print("(Expect some 200 OK and then 429 Too Many Requests)")
    headers = {"Authorization": f"Bearer {GENERATED_API_KEY}"}
    success_count = 0
    rate_limit_count = 0
    for i in range(1, 106):
        print(f"Request #{i}: ", end="")
        response = make_request("GET", f"{PROXY_URL}/", headers=headers, allow_redirects=False) # No redirects to see raw status
        if response:
            if response.status_code == 200:
                success_count += 1
                print("200 OK")
            elif response.status_code == 429:
                rate_limit_count += 1
                print("429 TOO MANY REQUESTS")
            else:
                print(f"Unexpected Status: {response.status_code}")
        else:
            print("No response")
        time.sleep(0.01) # Small delay to avoid overwhelming local network/CPU
    print(f"\nRate limiting test complete. Successful: {success_count}, Rate Limited: {rate_limit_count}")
    pause_script()

def test_update_subscription_inactive():
    """Test 6: Update Subscription Status to Inactive (Admin API)."""
    print_section_header("Test 6: Update Subscription Status to Inactive (Admin API)")
    headers = {
        "Content-Type": "application/json",
        "X-Admin-Secret": ADMIN_SECRET_KEY
    }
    data = {
        "userIdentifier": TEST_USER_IDENTIFIER,
        "subscriptionStatus": "inactive"
    }
    response = make_request("POST", f"{PROXY_URL}/api/update-subscription-status", headers=headers, data=data)
    if response and response.status_code == 200:
        print("SUCCESS: User subscription status updated to 'inactive'.")
    else:
        print(f"FAILURE: Could not set user to inactive. Status: {response.status_code if response else 'no response'}.")
    pause_script()

def test_unauthorized_after_inactive():
    """Test 7: User Access - Unauthorized (After Subscription Inactive)."""
    print_section_header("Test 7: User Access - Unauthorized (After Subscription Inactive)")
    if not GENERATED_API_KEY:
        print("Skipping: API Key not generated. Run Test 1 first.")
        pause_script()
        return

    headers = {"Authorization": f"Bearer {GENERATED_API_KEY}"}
    response = make_request("GET", f"{PROXY_URL}/", headers=headers)
    if response and response.status_code == 401:
        print("SUCCESS: Received 401 Unauthorized as expected after subscription became inactive.")
    else:
        print(f"FAILURE: Expected 401 Unauthorized, but got {response.status_code if response else 'no response'}.")
    pause_script()

# ###############################################################
# # Main Execution                                            #
# ###############################################################

if __name__ == "__main__":
    print("Starting Node.js HTTPS Proxy Test Script (Python)")
    print("Ensure your Node.js proxy is running on HTTPS (port 443) and MySQL is accessible.")
    print("Also, ensure 'key.pem' and 'cert.pem' are in your proxy's directory for HTTPS.")
    print(f"Proxy URL: {PROXY_URL}")
    print(f"Admin Secret Key: {ADMIN_SECRET_KEY}")
    print(f"Test User Identifier: {TEST_USER_IDENTIFIER}")
    pause_script()

    test_generate_api_key()

    # Exit if API key generation failed
    if not GENERATED_API_KEY:
        print("\nScript terminated: API Key generation failed. Cannot proceed with further tests.")
        exit(1)

    test_unauthorized_access()
    test_reauthorize_user() # Ensure user is active before authorized tests
    test_authorized_access_header()
    test_authorized_access_query()
    test_rate_limiting()
    test_update_subscription_inactive()
    test_unauthorized_after_inactive()

    print_section_header("All Tests Completed")
    print("Please review the output above.")

