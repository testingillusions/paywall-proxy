# --- Configuration ---
BASE_URL = "https://tba.testingillusions.com"
ADMIN_SECRET = "43cc3acc34b59a930b6dd52ba89c85d"
TEST_EMAIL = "joe.kayak+test@gmail.com"
TEST_PASSWORD = "test123>"
TEST_USER_IDENTIFIER = "joe.kayak+test@gmail.com"

import unittest
import requests
from urllib.parse import urljoin

session = requests.Session()

class APITestCase(unittest.TestCase):
    def test_01_healthcheck(self):
        url = urljoin(BASE_URL, "/healthcheck")
        r = session.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text.strip(), 'OK')

    def test_02_login_invalid(self):
        url = urljoin(BASE_URL, "/login")
        r = session.post(url, data={'email': 'wrong@example.com', 'password': 'badpass'})
        self.assertEqual(r.status_code, 401)

    def test_03_admin_generate_token(self):
        url = urljoin(BASE_URL, "/api/generate-token")
        headers = {'X-Admin-Secret': ADMIN_SECRET}
        payload = {'userIdentifier': TEST_USER_IDENTIFIER, 'subscriptionStatus': 'active'}
        r = session.post(url, headers=headers, json=payload)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn('apiKey', data)
        self.__class__.generated_api_key = data['apiKey']  # store for later tests
"""     def test_04_admin_update_subscription(self):
        url = urljoin(BASE_URL, "/api/update-subscription-status")
        headers = {'X-Admin-Secret': ADMIN_SECRET}
        payload = {'userIdentifier': TEST_USER_IDENTIFIER, 'subscriptionStatus': 'inactive'}
        r = session.post(url, headers=headers, json=payload)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data.get('subscriptionStatus'), 'inactive')

    def test_05_create_launch_token_unauthorized(self):
        url = urljoin(BASE_URL, "/api/create-launch-token")
        r = session.get(url)
        self.assertEqual(r.status_code, 401)

    def test_06_create_launch_token(self):
        # Reactivate user
        url_up = urljoin(BASE_URL, "/api/update-subscription-status")
        session.post(url_up, headers={'X-Admin-Secret': ADMIN_SECRET}, json={'userIdentifier': TEST_USER_IDENTIFIER, 'subscriptionStatus': 'active'})

        key = self.__class__.generated_api_key
        url = urljoin(BASE_URL, "/api/create-launch-token")
        r = session.get(url, headers={'Authorization': f'Bearer {key}'})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn('launch_url', data)
        self.__class__.launch_url = data['launch_url']

    def test_07_auth_launch(self):
        # Perform auth-launch and verify redirect
        r = session.get(self.__class__.launch_url, allow_redirects=False)
        self.assertIn(r.status_code, (302, 303))
        location = r.headers.get('Location', '')
        self.assertTrue(location.endswith('/'))

 """
if __name__ == '__main__':
    unittest.main(verbosity=2)
