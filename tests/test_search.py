from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User
from app.services.jwt_service import decode_token  # Corrected import for decode_token 
from app.utils.nickname_gen import generate_nickname  # If you use generated nicknames in tests

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "column,value,expected_status,expected_total",
    [
        ("first_name", "John", 200, 1),         # Valid search
        ("invalid_column", "John", 400, 0),    # Invalid column
        ("first_name", "NonexistentName", 404, 0),  # No results found
        ("email", "!@#$%^&*()", 404, 0),       # Invalid value with no results
    ]
)
async def test_search_users(
    async_client: AsyncClient, admin_token, column, value, expected_status, expected_total
):
    response = await async_client.get(
        "/users/search",
        params={"column": column, "value": value},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == expected_status
    if expected_status == 200:
        data = response.json()
        assert data["total"] >= expected_total
        assert len(data["items"]) >= expected_total

@pytest.mark.asyncio
async def test_search_users_case_insensitive(async_client: AsyncClient, admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "john"},  # Lowercase to test case insensitivity
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0
    assert any(user["first_name"].lower() == "john" for user in data["items"])

@pytest.mark.asyncio
async def test_search_users_without_authorization(async_client: AsyncClient):
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "John"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.asyncio
async def test_search_users_with_expired_token(async_client: AsyncClient, expired_admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "John"},
        headers={"Authorization": f"Bearer {expired_admin_token}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

@pytest.mark.asyncio
async def test_search_users_pagination(async_client: AsyncClient, admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "John", "skip": 0, "limit": 1},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["size"] == 1
    assert len(data["items"]) == 1

@pytest.mark.asyncio
async def test_search_users_multiple_results(
    async_client: AsyncClient, admin_token, preload_users_with_same_last_name
):
    response = await async_client.get(
        "/users/search",
        params={"column": "last_name", "value": "Smith"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 1
    assert all(user["last_name"] == "Smith" for user in data["items"])

@pytest.mark.asyncio
async def test_search_users_email_valid(async_client: AsyncClient, admin_token, preload_user_with_email):
    response = await async_client.get(
        "/users/search",
        params={"column": "email", "value": "alex.ross@example.com"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["email"] == "alex.ross@example.com"

@pytest.mark.asyncio
async def test_search_users_invalid_token_format(async_client: AsyncClient):
    """Test with a malformed token."""
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "John"},
        headers={"Authorization": "Bearer invalid.token.format"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

@pytest.mark.asyncio
async def test_search_users_sql_injection(async_client: AsyncClient, admin_token):
    """Test with a potential SQL injection attack."""
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "'; DROP TABLE users; --"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code in [400, 404]  # Ensure query fails securely
    assert "detail" in response.json()
