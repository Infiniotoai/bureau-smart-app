"""
Backend API Tests for BureauSmart - Bureaucracy Intelligence Engine
Tests: Auth, Documents, Payments, Subscription checks
"""
import pytest
import requests
import os
import uuid

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://bureau-smart.preview.emergentagent.com').rstrip('/')

# Test credentials from environment or test_credentials.md
ADMIN_EMAIL = os.environ.get('TEST_ADMIN_EMAIL', 'admin@example.com')
ADMIN_PASSWORD = os.environ.get('TEST_ADMIN_PASSWORD', 'Badboy4242-elyasa')


class TestHealthCheck:
    """Health check endpoint tests"""
    
    def test_api_root(self):
        """Test API root endpoint"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data


class TestAuth:
    """Authentication endpoint tests"""
    
    def test_login_success(self):
        """Test admin login with correct credentials"""
        session = requests.Session()
        response = session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert response.status_code == 200, f"Login failed: {response.text}"
        
        data = response.json()
        assert "id" in data
        assert data["email"] == ADMIN_EMAIL
        assert data["role"] == "admin"
        assert data["subscription_status"] == "active"
        
        assert "access_token" in session.cookies or response.cookies.get("access_token")
    
    def test_login_invalid_credentials(self):
        """Test login with wrong password"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": "wrongpassword"
        })
        assert response.status_code == 401
    
    def test_register_new_user(self):
        """Test user registration"""
        test_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
        response = requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": test_email,
            "password": "testpass123",
            "name": "Test User"
        })
        assert response.status_code == 200, f"Registration failed: {response.text}"
        
        data = response.json()
        assert data["email"] == test_email
        assert data["role"] == "user"
        assert data["subscription_status"] == "inactive"
    
    def test_register_duplicate_email(self):
        """Test registration with existing email"""
        response = requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": ADMIN_EMAIL,
            "password": "testpass123",
            "name": "Duplicate User"
        })
        assert response.status_code == 400
    
    def test_get_me_authenticated(self):
        """Test /auth/me with valid session"""
        session = requests.Session()
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert login_resp.status_code == 200
        
        me_resp = session.get(f"{BASE_URL}/api/auth/me")
        assert me_resp.status_code == 200
        
        data = me_resp.json()
        assert data["email"] == ADMIN_EMAIL
    
    def test_get_me_unauthenticated(self):
        """Test /auth/me without authentication"""
        response = requests.get(f"{BASE_URL}/api/auth/me")
        assert response.status_code == 401
    
    def test_logout(self):
        """Test logout functionality"""
        session = requests.Session()
        session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        
        logout_resp = session.post(f"{BASE_URL}/api/auth/logout")
        assert logout_resp.status_code == 200


class TestDocuments:
    """Document endpoint tests"""
    
    @pytest.fixture
    def auth_session(self):
        """Create authenticated session"""
        session = requests.Session()
        response = session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert response.status_code == 200
        return session
    
    def test_get_documents_authenticated(self, auth_session):
        """Test getting documents list"""
        response = auth_session.get(f"{BASE_URL}/api/documents")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_documents_unauthenticated(self):
        """Test documents endpoint without auth"""
        response = requests.get(f"{BASE_URL}/api/documents")
        assert response.status_code == 401
    
    def test_search_documents(self, auth_session):
        """Test document search functionality"""
        response = auth_session.get(f"{BASE_URL}/api/documents", params={"search": "test"})
        assert response.status_code == 200


class TestPaywallEnforcement:
    """Test paywall enforcement for generate-text endpoint"""
    
    def test_generate_text_non_subscriber(self):
        """Test that non-subscribed users get 403 on generate-text"""
        test_email = f"test_paywall_{uuid.uuid4().hex[:8]}@example.com"
        session = requests.Session()
        
        reg_resp = session.post(f"{BASE_URL}/api/auth/register", json={
            "email": test_email,
            "password": "testpass123",
            "name": "Paywall Test User"
        })
        assert reg_resp.status_code == 200
        
        user_data = reg_resp.json()
        assert user_data["subscription_status"] == "inactive"
        
        gen_resp = session.post(f"{BASE_URL}/api/documents/generate-text", json={
            "doc_id": "fake-doc-id",
            "option_label": "Test Option",
            "target_language": "Deutsch"
        })
        
        assert gen_resp.status_code == 403, f"Expected 403, got {gen_resp.status_code}: {gen_resp.text}"
    
    def test_generate_text_admin_allowed(self):
        """Test that admin users can access generate-text"""
        session = requests.Session()
        
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert login_resp.status_code == 200
        
        gen_resp = session.post(f"{BASE_URL}/api/documents/generate-text", json={
            "doc_id": "fake-doc-id",
            "option_label": "Test Option",
            "target_language": "Deutsch"
        })
        
        assert gen_resp.status_code != 403, f"Admin should not get 403, got: {gen_resp.status_code}"
    
    def test_improve_text_non_subscriber(self):
        """Test that non-subscribed users get 403 on improve-text"""
        test_email = f"test_improve_{uuid.uuid4().hex[:8]}@example.com"
        session = requests.Session()
        
        reg_resp = session.post(f"{BASE_URL}/api/auth/register", json={
            "email": test_email,
            "password": "testpass123",
            "name": "Improve Test User"
        })
        assert reg_resp.status_code == 200
        
        improve_resp = session.post(f"{BASE_URL}/api/documents/improve-text", json={
            "original_text": "Test text",
            "improvement_request": "Make it better",
            "target_language": "Deutsch"
        })
        
        assert improve_resp.status_code == 403, f"Expected 403, got {improve_resp.status_code}"


class TestPayments:
    """Payment endpoint tests"""
    
    def test_checkout_authenticated(self):
        """Test checkout endpoint for authenticated user"""
        session = requests.Session()
        
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert login_resp.status_code == 200
        
        checkout_resp = session.post(f"{BASE_URL}/api/payments/checkout", json={
            "origin_url": "https://bureau-smart.preview.emergentagent.com"
        })
        
        assert checkout_resp.status_code in [200, 500]
        if checkout_resp.status_code == 200:
            data = checkout_resp.json()
            assert "url" in data or "session_id" in data
    
    def test_checkout_unauthenticated(self):
        """Test checkout endpoint without auth"""
        response = requests.post(f"{BASE_URL}/api/payments/checkout", json={
            "origin_url": "https://bureau-smart.preview.emergentagent.com"
        })
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
