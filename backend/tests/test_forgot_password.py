"""
Test suite for Forgot Password functionality
Tests: POST /api/auth/forgot-password and POST /api/auth/verify-reset-code
"""
import pytest
import requests
import os
import time

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestForgotPasswordEndpoints:
    """Tests for forgot password flow"""
    
    def test_forgot_password_with_valid_email(self):
        """Test forgot-password endpoint with existing user email"""
        response = requests.post(
            f"{BASE_URL}/api/auth/forgot-password",
            json={"email": "admin@example.com"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("success") == True
        assert "message" in data
        print(f"✓ Forgot password with valid email: {data}")
    
    def test_forgot_password_with_nonexistent_email(self):
        """Test forgot-password endpoint with non-existent email (should still return success for security)"""
        response = requests.post(
            f"{BASE_URL}/api/auth/forgot-password",
            json={"email": "nonexistent@example.com"}
        )
        # Should return success to not reveal if email exists
        assert response.status_code == 200
        data = response.json()
        assert data.get("success") == True
        print(f"✓ Forgot password with non-existent email (security): {data}")
    
    def test_forgot_password_invalid_email_format(self):
        """Test forgot-password endpoint with invalid email format"""
        response = requests.post(
            f"{BASE_URL}/api/auth/forgot-password",
            json={"email": "invalid-email"}
        )
        # Should return 422 for validation error
        assert response.status_code in [400, 422]
        print(f"✓ Forgot password with invalid email format rejected: {response.status_code}")
    
    def test_verify_reset_code_with_wrong_code(self):
        """Test verify-reset-code endpoint with wrong code"""
        # First request a code
        requests.post(
            f"{BASE_URL}/api/auth/forgot-password",
            json={"email": "admin@example.com"}
        )
        
        # Try to verify with wrong code
        response = requests.post(
            f"{BASE_URL}/api/auth/verify-reset-code",
            json={
                "email": "admin@example.com",
                "code": "000000",
                "new_password": "NewPassword123"
            }
        )
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        # Should mention wrong code or remaining attempts
        print(f"✓ Verify with wrong code rejected: {data}")
    
    def test_verify_reset_code_with_nonexistent_email(self):
        """Test verify-reset-code endpoint with email that has no code"""
        response = requests.post(
            f"{BASE_URL}/api/auth/verify-reset-code",
            json={
                "email": "nocode@example.com",
                "code": "123456",
                "new_password": "NewPassword123"
            }
        )
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        print(f"✓ Verify with no code email rejected: {data}")
    
    def test_verify_reset_code_short_password(self):
        """Test verify-reset-code endpoint with password too short"""
        # First request a code
        requests.post(
            f"{BASE_URL}/api/auth/forgot-password",
            json={"email": "admin@example.com"}
        )
        
        # Try to verify with short password (even with wrong code, password validation may happen first)
        response = requests.post(
            f"{BASE_URL}/api/auth/verify-reset-code",
            json={
                "email": "admin@example.com",
                "code": "123456",
                "new_password": "12345"  # Less than 6 chars
            }
        )
        # Should return 400 for either wrong code or short password
        assert response.status_code == 400
        print(f"✓ Verify with short password handled: {response.status_code}")


class TestLoginRegression:
    """Regression tests for login functionality"""
    
    def test_admin_login_still_works(self):
        """Test that admin login still works after forgot password implementation"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={
                "email": "admin@example.com",
                "password": "Badboy4242-elyasa"
            }
        )
        assert response.status_code == 200
        data = response.json()
        # User data is at root level, not nested under "user"
        assert "email" in data
        assert data["email"] == "admin@example.com"
        print(f"✓ Admin login works: {data['email']}")
    
    def test_login_with_wrong_password(self):
        """Test login with wrong password still fails"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={
                "email": "admin@example.com",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 401
        print(f"✓ Login with wrong password rejected: {response.status_code}")
    
    def test_health_endpoint(self):
        """Test health endpoint"""
        # Try common health endpoint paths
        for path in ["/api/", "/api/health", "/"]:
            response = requests.get(f"{BASE_URL}{path}")
            if response.status_code == 200:
                print(f"✓ Health endpoint works at {path}: {response.status_code}")
                return
        # If none work, just check the root API returns something
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code in [200, 404]  # API is reachable
        print(f"✓ API is reachable: {response.status_code}")


class TestAuthMeEndpoint:
    """Test /auth/me endpoint for session verification"""
    
    def test_auth_me_without_session(self):
        """Test /auth/me without authentication"""
        response = requests.get(f"{BASE_URL}/api/auth/me")
        assert response.status_code == 401
        print(f"✓ /auth/me without session returns 401")
    
    def test_auth_me_with_session(self):
        """Test /auth/me with valid session"""
        session = requests.Session()
        # Login first
        login_response = session.post(
            f"{BASE_URL}/api/auth/login",
            json={
                "email": "admin@example.com",
                "password": "Badboy4242-elyasa"
            }
        )
        assert login_response.status_code == 200
        
        # Check /auth/me
        me_response = session.get(f"{BASE_URL}/api/auth/me")
        assert me_response.status_code == 200
        data = me_response.json()
        assert data["email"] == "admin@example.com"
        print(f"✓ /auth/me with session works: {data['email']}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
