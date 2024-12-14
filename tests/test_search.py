from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User
from app.services.jwt_service import decode_token  # Corrected import for decode_token 
from app.utils.nickname_gen import generate_nickname  # If you use generated nicknames in tests

@pytest.mark.asyncio
async def test_search_users_by_email_success(async_client: AsyncClient, admin_token, preload_user_with_email):
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
async def test_search_users_by_first_name_success(async_client: AsyncClient, admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "John"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0  # Ensure some users are returned
    assert any(user["first_name"] == "John" for user in data["items"])


@pytest.mark.asyncio
async def test_search_users_by_first_name_success(async_client: AsyncClient, admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "John"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0  # Ensure some users are returned
    assert any(user["first_name"] == "John" for user in data["items"])


@pytest.mark.asyncio
async def test_search_users_by_invalid_column(async_client: AsyncClient, admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "invalid_column", "value": "John"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid column: invalid_column"

@pytest.mark.asyncio
async def test_search_users_no_results_found(async_client: AsyncClient, admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "NonexistentName"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "No users found"

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
async def test_search_users_case_insensitive(async_client: AsyncClient, admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "first_name", "value": "john"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0  # Ensure some users are returned
    assert any(user["first_name"].lower() == "john" for user in data["items"])

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
async def test_search_users_invalid_value(async_client: AsyncClient, admin_token):
    response = await async_client.get(
        "/users/search",
        params={"column": "email", "value": "!@#$%^&*()"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "No users found"

@pytest.mark.asyncio
async def test_search_users_multiple_results(async_client: AsyncClient, admin_token, preload_users_with_same_last_name):
    response = await async_client.get(
        "/users/search",
        params={"column": "last_name", "value": "Smith"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 1
    assert all(user["last_name"] == "Smith" for user in data["items"])
