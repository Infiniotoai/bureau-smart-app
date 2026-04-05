import requests
import sys
from datetime import datetime

class BureaucracyEngineAPITester:
    def __init__(self, base_url="https://bureau-smart.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tests_run = 0
        self.tests_passed = 0
        self.admin_email = "admin@example.com"
        self.admin_password = "admin123"

    def run_test(self, name, method, endpoint, expected_status, data=None, files=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers)
            elif method == 'POST':
                if files:
                    # Remove Content-Type for file uploads
                    headers.pop('Content-Type', None)
                    response = self.session.post(url, data=data, files=files, headers=headers)
                else:
                    response = self.session.post(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = self.session.delete(url, headers=headers)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                if response.content:
                    try:
                        resp_json = response.json()
                        print(f"   Response: {resp_json}")
                        return True, resp_json
                    except:
                        return True, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                try:
                    error_detail = response.json()
                    print(f"   Error: {error_detail}")
                except:
                    print(f"   Error: {response.text}")

            return success, response.json() if success and response.content else {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_health_check(self):
        """Test API health check"""
        return self.run_test("API Health Check", "GET", "", 200)

    def test_admin_login(self):
        """Test admin login"""
        success, response = self.run_test(
            "Admin Login",
            "POST",
            "auth/login",
            200,
            data={"email": self.admin_email, "password": self.admin_password}
        )
        if success:
            print(f"   Admin user: {response.get('name')} ({response.get('role')})")
            print(f"   Subscription: {response.get('subscription_status')}")
        return success

    def test_user_registration(self):
        """Test user registration"""
        test_user_email = f"test_user_{datetime.now().strftime('%H%M%S')}@example.com"
        success, response = self.run_test(
            "User Registration",
            "POST",
            "auth/register",
            200,
            data={
                "email": test_user_email,
                "password": "TestPass123!",
                "name": "Test User"
            }
        )
        if success:
            print(f"   New user: {response.get('name')} ({response.get('email')})")
        return success

    def test_auth_me(self):
        """Test getting current user info"""
        return self.run_test("Get Current User", "GET", "auth/me", 200)

    def test_logout(self):
        """Test logout"""
        return self.run_test("Logout", "POST", "auth/logout", 200)

    def test_documents_list(self):
        """Test getting documents list"""
        return self.run_test("Get Documents", "GET", "documents", 200)

    def test_protected_route_without_auth(self):
        """Test accessing protected route without authentication"""
        # Create new session without auth
        temp_session = requests.Session()
        url = f"{self.base_url}/documents"
        
        print(f"\n🔍 Testing Protected Route Without Auth...")
        print(f"   URL: {url}")
        
        try:
            response = temp_session.get(url)
            success = response.status_code == 401
            self.tests_run += 1
            
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code} (Correctly rejected)")
            else:
                print(f"❌ Failed - Expected 401, got {response.status_code}")
            
            return success
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False

def main():
    print("🚀 Starting Bureaucracy Intelligence Engine API Tests")
    print("=" * 60)
    
    tester = BureaucracyEngineAPITester()
    
    # Test sequence
    tests = [
        ("API Health Check", tester.test_health_check),
        ("Admin Login", tester.test_admin_login),
        ("Get Current User", tester.test_auth_me),
        ("User Registration", tester.test_user_registration),
        ("Get Documents", tester.test_documents_list),
        ("Protected Route (No Auth)", tester.test_protected_route_without_auth),
        ("Logout", tester.test_logout),
    ]
    
    failed_tests = []
    
    for test_name, test_func in tests:
        try:
            success = test_func()
            if not success:
                failed_tests.append(test_name)
        except Exception as e:
            print(f"❌ {test_name} - Exception: {str(e)}")
            failed_tests.append(test_name)
    
    # Print results
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {tester.tests_passed}/{tester.tests_run} passed")
    
    if failed_tests:
        print(f"\n❌ Failed tests:")
        for test in failed_tests:
            print(f"   - {test}")
    else:
        print("\n✅ All tests passed!")
    
    return 0 if len(failed_tests) == 0 else 1

if __name__ == "__main__":
    sys.exit(main())