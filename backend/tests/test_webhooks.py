import base64
import hashlib
import hmac

from app.api import webhooks


def _signature(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def test_shopify_hmac_fails_closed_without_secret(monkeypatch):
    body = b'{"id": 123}'
    monkeypatch.setattr(webhooks.settings, "SHOPIFY_API_SECRET", "")

    assert webhooks._verify_shopify_hmac(body, _signature(body, "secret")) is False


def test_shopify_hmac_accepts_valid_signature(monkeypatch):
    body = b'{"id": 123}'
    secret = "shopify-app-secret"
    monkeypatch.setattr(webhooks.settings, "SHOPIFY_API_SECRET", secret)

    assert webhooks._verify_shopify_hmac(body, _signature(body, secret)) is True


def test_shopify_hmac_rejects_invalid_signature(monkeypatch):
    monkeypatch.setattr(webhooks.settings, "SHOPIFY_API_SECRET", "shopify-app-secret")

    assert webhooks._verify_shopify_hmac(b'{"id": 123}', "not-valid") is False


def test_normalize_shop_domain_requires_explicit_domain():
    assert webhooks._normalize_shop_domain("") is None
    assert webhooks._normalize_shop_domain(" HTTPS://Example.myshopify.com/ ") == (
        "example.myshopify.com"
    )
