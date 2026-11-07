"""In-App SOC Notification Centre endpoints (`/api/v1/notifications`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.core.rbac import require_authenticated_user
from app.db.session import get_db_session
from app.models.ops import Notification
from app.models.user import User
from app.schemas.evidence import NotificationItemOut, NotificationListOut

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=NotificationListOut)
async def list_my_notifications(
    limit: int = Query(default=30, ge=1, le=100),
    user: User = Depends(require_authenticated_user()),
    db: AsyncSession = Depends(get_db_session),
) -> NotificationListOut:
    role_name = user.role.name if user.role else "soc_l1"
    visibility_clause = or_(
        Notification.user_id == user.id,
        Notification.role_target == role_name,
        Notification.user_id.is_(None) & Notification.role_target.is_(None),
    )

    unread_stmt = select(func.count(Notification.id)).where(
        visibility_clause,
        Notification.is_read.is_(False),
    )
    unread_count = int((await db.execute(unread_stmt)).scalar_one())

    stmt = (
        select(Notification)
        .where(visibility_clause)
        .order_by(Notification.created_at.desc())
        .limit(limit)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return NotificationListOut(
        items=[NotificationItemOut.model_validate(r) for r in rows],
        unread_count=unread_count,
    )


@router.post("/{notification_id}/read", response_model=NotificationItemOut)
async def mark_notification_read(
    notification_id: uuid.UUID,
    user: User = Depends(require_authenticated_user()),
    db: AsyncSession = Depends(get_db_session),
) -> NotificationItemOut:
    role_name = user.role.name if user.role else "soc_l1"
    res = await db.execute(select(Notification).where(Notification.id == notification_id))
    notif = res.scalar_one_or_none()
    if notif is None or (
        notif.user_id is not None
        and notif.user_id != user.id
        and notif.role_target != role_name
    ):
        raise AppError("NOTIFICATION_NOT_FOUND", "Notification not found.", 404)

    notif.is_read = True
    notif.read_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(notif)
    return NotificationItemOut.model_validate(notif)


@router.post("/read-all", status_code=status.HTTP_204_NO_CONTENT)
async def mark_all_notifications_read(
    user: User = Depends(require_authenticated_user()),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    role_name = user.role.name if user.role else "soc_l1"
    visibility_clause = or_(
        Notification.user_id == user.id,
        Notification.role_target == role_name,
        Notification.user_id.is_(None) & Notification.role_target.is_(None),
    )
    await db.execute(
        update(Notification)
        .where(visibility_clause, Notification.is_read.is_(False))
        .values(is_read=True, read_at=datetime.now(UTC))
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

