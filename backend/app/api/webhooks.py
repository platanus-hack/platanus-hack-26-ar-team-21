"""Webhooks entrantes de integraciones externas.

Shopify llama a POST /webhooks/shopify/orders cuando se crea una orden.
Vera cuenta las ventas nuevas desde el último AgentRun y, si alcanzan el
umbral configurado en SHOPIFY_TRIGGER_EVERY_N_ORDERS, lanza run_vera()
en background.
"""
import asyncio
import base64
import hashlib
import hmac as hmac_mod
import json
import logging
import uuid
from datetime import UTC, datetime
from decimal import Decimal

from fastapi import APIRouter, Header, HTTPException, Request, status
from sqlalchemy import func, select

from app.agent.graph import run_vera
from app.core.config import settings
from app.core.deps import DbSession
from app.db.models import AgentRun, Merchant, Product, Sale
from app.db.session import async_session_factory

logger = logging.getLogger("vera.webhooks")
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _verify_shopify_hmac(body: bytes, signature: str) -> bool:
    """Valida la firma HMAC-SHA256 que Shopify adjunta en cada webhook."""
    if not settings.SHOPIFY_API_SECRET or not signature:
        return False
    expected = base64.b64encode(
        hmac_mod.new(settings.SHOPIFY_API_SECRET.encode(), body, hashlib.sha256).digest()
    ).decode()
    return hmac_mod.compare_digest(expected, signature.strip())


def _normalize_shop_domain(raw: str) -> str | None:
    normalized = raw.strip().lower()
    if not normalized:
        return None
    normalized = normalized.removeprefix("https://").removeprefix("http://").rstrip("/")
    if not normalized:
        return None
    return normalized


async def _run_vera_background(merchant_id: uuid.UUID) -> None:
    async with async_session_factory() as db:
        try:
            await run_vera(merchant_id, db, trigger="shopify_order")
        except Exception:
            logger.exception("run_vera background failed for merchant=%s", merchant_id)


@router.post("/shopify/orders", status_code=status.HTTP_200_OK)
async def shopify_order_webhook(
    request: Request,
    db: DbSession,
    x_shopify_hmac_sha256: str = Header(default=""),
    x_shopify_shop_domain: str = Header(default=""),
) -> dict:
    """Recibe órdenes nuevas de Shopify y activa Vera cuando corresponde."""
    body = await request.body()

    if not settings.SHOPIFY_API_SECRET:
        logger.error("shopify webhook rejected: SHOPIFY_API_SECRET is not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook de Shopify no configurado",
        )

    if not _verify_shopify_hmac(body, x_shopify_hmac_sha256):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="HMAC inválido")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="JSON inválido",
        ) from exc

    # Identificar merchant por dominio de la tienda que Shopify firma.
    shop_domain = _normalize_shop_domain(x_shopify_shop_domain)
    if shop_domain is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Falta X-Shopify-Shop-Domain",
        )
    merchant = (
        await db.execute(select(Merchant).where(Merchant.shopify_shop_domain == shop_domain))
    ).scalar_one_or_none()

    if merchant is None:
        logger.warning("webhook shopify: no merchant encontrado para domain=%s", shop_domain)
        return {"status": "ignored", "reason": "merchant not found"}

    order_id = str(payload.get("id", ""))
    line_items = payload.get("line_items", [])
    created_at_raw = payload.get("created_at")

    try:
        sold_at = (
            datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
            if created_at_raw
            else datetime.now(UTC)
        )
    except (ValueError, AttributeError):
        sold_at = datetime.now(UTC)

    # Persistir productos y ventas de cada line item
    for item in line_items:
        external_product_id = str(item.get("product_id") or "")
        if not external_product_id or external_product_id == "None":
            continue

        # Upsert producto (datos mínimos si no existe aún)
        product = (
            await db.execute(
                select(Product).where(
                    Product.merchant_id == merchant.id,
                    Product.external_id == external_product_id,
                )
            )
        ).scalar_one_or_none()

        if product is None:
            product = Product(
                merchant_id=merchant.id,
                external_id=external_product_id,
                name=item.get("title") or "Producto",
                price=Decimal(str(item.get("price") or "0")),
            )
            db.add(product)
            await db.flush()

        # Upsert venta (la constraint uq_sales_merchant_order_product garantiza idempotencia)
        existing_sale = (
            await db.execute(
                select(Sale).where(
                    Sale.merchant_id == merchant.id,
                    Sale.external_order_id == order_id,
                    Sale.product_id == product.id,
                )
            )
        ).scalar_one_or_none()

        if existing_sale is None:
            quantity = item.get("quantity") or 1
            db.add(
                Sale(
                    merchant_id=merchant.id,
                    product_id=product.id,
                    external_order_id=order_id,
                    quantity=quantity,
                    revenue=Decimal(str(item.get("price") or "0")) * quantity,
                    sold_at=sold_at,
                )
            )

    await db.commit()

    # Contar ventas nuevas desde el último AgentRun del merchant
    last_run = (
        await db.execute(
            select(AgentRun)
            .where(AgentRun.merchant_id == merchant.id)
            .order_by(AgentRun.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    count_q = select(func.count(Sale.id)).where(Sale.merchant_id == merchant.id)
    if last_run is not None:
        count_q = count_q.where(Sale.sold_at > last_run.created_at)

    sales_since_last_run: int = (await db.execute(count_q)).scalar_one()
    threshold = merchant.shopify_trigger_every_n_orders

    logger.info(
        "shopify webhook | merchant=%s domain=%s sales_since_last_run=%d threshold=%d",
        merchant.id,
        shop_domain,
        sales_since_last_run,
        threshold,
    )

    if sales_since_last_run >= threshold:
        logger.info(
            "Activando Vera para merchant=%s (ventas=%d)",
            merchant.id,
            sales_since_last_run,
        )
        asyncio.create_task(_run_vera_background(merchant.id))

    return {"status": "ok", "sales_since_last_run": sales_since_last_run, "threshold": threshold}
