from __future__ import annotations

from datetime import timedelta
from decimal import Decimal, InvalidOperation

from lumica.domain.models import AuthIdentity, PanelTemplate, Region, SubscriptionItem, SubscriptionPlan, User
from lumica.services import subscriptions as subscriptions_service

def register_auth_routes(app, deps):
    # Transitional dependency injection while handlers are being migrated out
    # of shared app helper closures.
    globals().update(deps)

    def _int_or_error(value, field: str, *, default: int | None = None, min_value: int | None = None):
        if value in (None, ""):
            return default, None
        try:
            out = int(value)
        except (TypeError, ValueError):
            return None, (jsonify({"ok": False, "error": f"{field} must be an integer"}), 400)
        if min_value is not None and out < min_value:
            return None, (jsonify({"ok": False, "error": f"{field} must be >= {min_value}"}), 400)
        return out, None

    def _plan_meta(plan: SubscriptionPlan) -> dict:
        return subscriptions_service.plan_meta(plan)

    def _plan_item_price_map(plan: SubscriptionPlan) -> dict[tuple[str | None, str], Decimal]:
        return subscriptions_service.plan_item_price_map(plan)

    def _pricing_error_response(exc: subscriptions_service.PricingError):
        return jsonify({"ok": False, "error": str(exc)}), exc.status_code

    def _resolve_plan(db, payload: dict):
        try:
            return subscriptions_service.resolve_plan(db, payload), None
        except subscriptions_service.PricingError as exc:
            return None, _pricing_error_response(exc)

    def _require_verified_user(db, user_id: int):
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None, (jsonify({"ok": False, "error": "Unauthorized"}), 401)
        status = (user.status or "").strip().lower()
        if status != "verified":
            return None, (jsonify({"ok": False, "error": "Verification required"}), 403)
        return user, None

    def _subscription_duration_months(plan: SubscriptionPlan, payload: dict):
        try:
            return subscriptions_service.subscription_duration_months(plan, payload), None
        except subscriptions_service.PricingError as exc:
            return None, _pricing_error_response(exc)

    def _calculate_subscription_pricing(plan: SubscriptionPlan, payload: dict):
        try:
            return subscriptions_service.calculate_subscription_pricing(plan, payload), None
        except subscriptions_service.PricingError as exc:
            return None, _pricing_error_response(exc)

    def _serialize_plan(plan: SubscriptionPlan) -> dict:
        return {
            "id": plan.id,
            "name": plan.name,
            "is_active": bool(plan.is_active),
            "base_price": str(plan.base_price) if plan.base_price is not None else None,
            "meta": plan.meta_json if isinstance(plan.meta_json, dict) else {},
        }

    def _serialize_region(region: Region) -> dict:
        return {
            "id": region.id,
            "code": region.code,
            "name": region.name,
            "is_active": bool(region.is_active),
        }

    def _serialize_template(template: PanelTemplate) -> dict:
        return {
            "id": template.id,
            "name": template.name,
            "protocol": template.protocol,
            "apply_mode": template.apply_mode,
            "settings": template.settings if isinstance(template.settings, dict) else {},
        }

    def _serialize_subscription(subscription: Subscription) -> dict:
        return {
            "id": subscription.id,
            "status": subscription.status,
            "access_until": subscription.access_until.isoformat() if subscription.access_until else None,
            "price_amount": str(subscription.price_amount) if subscription.price_amount is not None else None,
            "total_price": str(subscription.total_price) if subscription.total_price is not None else None,
            "payload": subscription.payload if isinstance(subscription.payload, dict) else {},
            "notes": subscription.notes,
        }

    def _find_identity(db, provider: str, provider_user_id: str) -> AuthIdentity | None:
        return (
            db.query(AuthIdentity)
            .filter(AuthIdentity.provider == provider, AuthIdentity.provider_user_id == provider_user_id)
            .first()
        )

    def _ensure_identity(db, user: User, provider: str, provider_user_id: str) -> tuple[AuthIdentity, bool] | tuple[None, tuple]:
        existing = _find_identity(db, provider, provider_user_id)
        if existing:
            if existing.user_id != user.id:
                return None, (jsonify({"ok": False, "error": "Identity already linked"}), 409)
            return existing, False
        identity = AuthIdentity(user_id=user.id, provider=provider, provider_user_id=provider_user_id)
        db.add(identity)
        db.flush()
        return identity, True

    def _get_or_create_user_by_identity(db, provider: str, provider_user_id: str) -> tuple[User, bool]:
        identity = _find_identity(db, provider, provider_user_id)
        if identity:
            user = db.query(User).filter(User.id == identity.user_id).first()
            if user:
                return user, False
            user = User()
            db.add(user)
            db.flush()
            identity.user_id = user.id
            return user, True

        user = None
        if provider == "telegram":
            user = db.query(User).filter(User.telegram_id == provider_user_id).first()
        elif provider == "phone":
            user = db.query(User).filter(User.phone == provider_user_id).first()

        if not user:
            user = User()
            db.add(user)
            db.flush()

        _ensure_identity(db, user, provider, provider_user_id)
        return user, True

    @app.post("/api/tg/auth")
    def tg_auth():
        body = request.get_json(silent=True) or {}
        init_data = body.get("initData", "")

        try:
            user_data = validate_init_data(init_data)
        except Exception:
            app.logger.exception("tg_auth validation failed")
            return jsonify({"ok": False, "error": "Server error validating initData"}), 500

        if not user_data:
            return jsonify({"ok": False, "error": "Invalid initData"}), 401

        try:
            with SessionLocal() as db:
                telegram_id = str(user_data.get("id", ""))
                user, _ = _get_or_create_user_by_identity(db, "telegram", telegram_id)

                user.telegram_id = telegram_id
                user.username = user_data.get("username")
                first_name = user_data.get("first_name")
                last_name = user_data.get("last_name")
                name = " ".join(filter(None, [first_name, last_name])).strip()
                user.name = name or user.username
                if telegram_id in role_bindings:
                    user.role = role_bindings[telegram_id]
                elif not user.role:
                    user.role = "user"

                if not getattr(user, "status", None):
                    user.status = "unverified"
                if user.role in {"owner", "admin", "support", "moderator"}:
                    user.status = "verified"

                now = utcnow()
                old_profile = user.profile_data or {}
                last_seen_raw = old_profile.get("last_seen")
                last_seen = None
                if isinstance(last_seen_raw, str):
                    try:
                        last_seen = datetime.fromisoformat(last_seen_raw)
                        if last_seen.tzinfo is None:
                            last_seen = last_seen.replace(tzinfo=timezone.utc)
                    except ValueError:
                        last_seen = None

                cooldown_minutes = int(os.getenv("ANIMATION_COOLDOWN_MINUTES", "720"))
                show_long_intro = last_seen is None or now - last_seen > timedelta(minutes=cooldown_minutes)

                merged_profile = {
                    **old_profile,
                    **user_data,
                    "last_seen": now.isoformat(),
                    "visit_count": int(old_profile.get("visit_count", 0)) + 1,
                }
                user.profile_data = merged_profile
                applied_pending_bindings = _apply_pending_bindings_for_user(db, user)
                db.commit()

                raw_session_token, raw_csrf_token = _new_session(db, user, init_data)
        except SQLAlchemyError:
            app.logger.exception("tg_auth: database error")
            return jsonify({"ok": False, "error": "Database error, please try again later"}), 500

        response = make_response(
            jsonify(
                {
                    "ok": True,
                    "user": user_data,
                    "first_visit": last_seen is None,
                    "show_long_intro": show_long_intro,
                    "applied_pending_bindings": applied_pending_bindings,
                    "csrf_token": raw_csrf_token,
                }
            )
        )
        cookie_secure = _env_bool("COOKIE_SECURE", True)
        same_site = os.getenv("COOKIE_SAMESITE", "Lax").strip().capitalize()
        if same_site not in {"Lax", "Strict", "None"}:
            same_site = "Lax"
        response.set_cookie(
            session_cookie_name,
            raw_session_token,
            httponly=True,
            secure=cookie_secure,
            samesite=same_site,
            max_age=session_ttl_days * 24 * 60 * 60,
            path="/",
        )
        return response

    @app.post("/api/auth/logout")
    def logout():
        raw_token = request.cookies.get(session_cookie_name)
        if raw_token:
            token_hash = _token_hash(raw_token)
            with SessionLocal() as db:
                db.query(AuthSession).filter(AuthSession.session_token == token_hash).delete()
                db.commit()

        response = make_response(jsonify({"ok": True}))
        response.delete_cookie(session_cookie_name, path="/")
        return response

    @app.get("/api/me")
    def me():
        auth, err = _auth_context()
        if err:
            return err

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == auth["user_id"]).first()
            if not user:
                return jsonify({"ok": False, "error": "Unauthorized"}), 401

            sub = _active_subscription(db, user.id)
            cloud_enabled = _cloud_visibility_enabled(db)
            return jsonify(
                {
                    "ok": True,
                    "user": {
                        "id": user.id,
                        "telegram_id": user.telegram_id,
                        "username": user.username,
                        "name": user.name,
                        "role": user.role,
                        "status": getattr(user, "status", None),
                    },
                    "subscription": None
                    if not sub
                    else {
                        "status": sub.status,
                        "access_until": sub.access_until.isoformat() if sub.access_until else None,
                        "price_amount": str(sub.price_amount) if sub.price_amount is not None else None,
                    },
                    "features": {
                        "cloud_enabled": cloud_enabled,
                    },
                }
            )

    @app.get("/api/subscription/options")
    def subscription_options():
        auth, err = _auth_context()
        if err:
            return err

        with SessionLocal() as db:
            _, err = _require_verified_user(db, auth["user_id"])
            if err:
                return err

            plans = (
                db.query(SubscriptionPlan)
                .filter(SubscriptionPlan.is_active == 1)
                .order_by(SubscriptionPlan.id.asc())
                .all()
            )
            regions = (
                db.query(Region)
                .filter(Region.is_active == 1)
                .order_by(Region.name.asc())
                .all()
            )
            templates = (
                db.query(PanelTemplate)
                .order_by(PanelTemplate.name.asc())
                .all()
            )
            return jsonify(
                {
                    "ok": True,
                    "plans": [_serialize_plan(plan) for plan in plans],
                    "regions": [_serialize_region(region) for region in regions],
                    "templates": [_serialize_template(template) for template in templates],
                }
            )

    @app.post("/api/subscription/draft")
    def subscription_draft():
        auth, err = _auth_context()
        if err:
            return err

        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            _, err = _require_verified_user(db, auth["user_id"])
            if err:
                return err

            plan, err = _resolve_plan(db, body)
            if err:
                return err

            pricing, err = _calculate_subscription_pricing(plan, body)
            if err:
                return err

            draft_id_raw = body.get("draft_id") or body.get("subscription_id")
            draft = None
            if draft_id_raw not in (None, ""):
                try:
                    draft_id = int(draft_id_raw)
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error": "draft_id must be an integer"}), 400
                draft = (
                    db.query(Subscription)
                    .filter(Subscription.id == draft_id, Subscription.user_id == auth["user_id"])
                    .first()
                )
                if not draft:
                    return jsonify({"ok": False, "error": "Draft not found"}), 404
                if (draft.status or "").strip().lower() not in {"draft", "inactive"}:
                    return jsonify({"ok": False, "error": "Only draft subscriptions can be updated"}), 400
            else:
                draft = Subscription(user_id=auth["user_id"], status="draft")
                db.add(draft)
                db.flush()

            payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
            payload = {
                **payload,
                "plan_id": plan.id,
                "plan_name": plan.name,
                "duration_months": pricing["duration_months"],
                "lifetime": pricing["is_lifetime"],
                "items": [
                    {
                        "item_type": item["item_type"],
                        "code": item["code"],
                        "quantity": item["quantity"],
                        "price": str(item["price"]),
                        "meta": item.get("meta", {}),
                    }
                    for item in pricing["items"]
                ],
                "region_code": body.get("region_code") or body.get("regionCode"),
                "connections_limit": body.get("connections_limit") or body.get("connectionsLimit"),
            }

            draft.payload = payload
            draft.price_amount = pricing["total"]
            draft.total_price = pricing["total"]
            draft.access_until = None

            db.query(SubscriptionItem).filter(SubscriptionItem.subscription_id == draft.id).delete()
            for item in pricing["items"]:
                db.add(
                    SubscriptionItem(
                        subscription_id=draft.id,
                        item_type=item["item_type"],
                        code=item["code"],
                        price=item["price"],
                        quantity=item["quantity"],
                        meta_json=item.get("meta", {}),
                    )
                )

            db.commit()
            db.refresh(draft)

            return jsonify(
                {
                    "ok": True,
                    "draft": _serialize_subscription(draft),
                    "pricing": {
                        "duration_months": pricing["duration_months"],
                        "is_lifetime": pricing["is_lifetime"],
                        "base_price": str(pricing["base_price"]),
                        "items_total": str(pricing["items_total"]),
                        "total": str(pricing["total"]),
                        "items": [
                            {
                                "item_type": item["item_type"],
                                "code": item["code"],
                                "price": str(item["price"]),
                                "quantity": item["quantity"],
                                "total": str(item["total"]),
                                "meta": item.get("meta", {}),
                            }
                            for item in pricing["items"]
                        ],
                    },
                }
            )

    @app.post("/api/subscription/confirm")
    def subscription_confirm():
        auth, err = _auth_context()
        if err:
            return err

        body = request.get_json(silent=True) or {}
        draft_id_raw = body.get("draft_id") or body.get("subscription_id")
        if draft_id_raw in (None, ""):
            return jsonify({"ok": False, "error": "draft_id is required"}), 400
        try:
            draft_id = int(draft_id_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "draft_id must be an integer"}), 400

        with SessionLocal() as db:
            _, err = _require_verified_user(db, auth["user_id"])
            if err:
                return err

            draft = (
                db.query(Subscription)
                .filter(Subscription.id == draft_id, Subscription.user_id == auth["user_id"])
                .first()
            )
            if not draft:
                return jsonify({"ok": False, "error": "Draft not found"}), 404

            if (draft.status or "").strip().lower() not in {"draft", "inactive"}:
                return jsonify({"ok": False, "error": "Only draft subscriptions can be confirmed"}), 400

            payload = draft.payload if isinstance(draft.payload, dict) else {}
            plan_payload = {
                "plan_id": payload.get("plan_id"),
                "plan_name": payload.get("plan_name"),
                "duration_months": payload.get("duration_months"),
                "items": payload.get("items"),
                "lifetime": payload.get("lifetime"),
            }
            plan, err = _resolve_plan(db, plan_payload)
            if err:
                return err

            pricing, err = _calculate_subscription_pricing(plan, plan_payload)
            if err:
                return err

            draft.price_amount = pricing["total"]
            draft.total_price = pricing["total"]
            if pricing["is_lifetime"]:
                draft.status = "lifetime"
                draft.access_until = None
            else:
                draft.status = "active"
                duration_months = max(pricing["duration_months"], 1)
                draft.access_until = utcnow() + timedelta(days=30 * duration_months)

            payload["confirmed_at"] = utcnow().isoformat()
            payload["status"] = draft.status
            draft.payload = payload

            db.commit()
            db.refresh(draft)

            return jsonify(
                {
                    "ok": True,
                    "subscription": _serialize_subscription(draft),
                    "pricing": {
                        "duration_months": pricing["duration_months"],
                        "is_lifetime": pricing["is_lifetime"],
                        "base_price": str(pricing["base_price"]),
                        "items_total": str(pricing["items_total"]),
                        "total": str(pricing["total"]),
                    },
                }
            )

    @app.post("/api/verify")
    def verify_user():
        auth, err = _auth_context()
        if err:
            return err

        body = request.get_json(silent=True) or {}
        code = str(body.get("code") or "").strip()
        if not code:
            return jsonify({"ok": False, "error": "code is required"}), 400

        phone = str(body.get("phone") or body.get("phone_number") or "").strip()
        if not phone:
            phone = None

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == auth["user_id"]).first()
            if not user:
                return jsonify({"ok": False, "error": "Unauthorized"}), 401

            row = (
                db.query(VerificationCode)
                .filter(VerificationCode.code == code, VerificationCode.status == "active")
                .first()
            )
            if not row:
                return jsonify({"ok": False, "error": "Invalid or used code"}), 404

            user.status = "verified"
            row.status = "used"
            row.used_by = user.id
            row.used_at = utcnow()

            db.add(
                UserVerification(
                    user_id=user.id,
                    method="code",
                    code_id=row.id,
                    approved_by=None,
                )
            )

            if phone:
                user.phone = phone
                _, err = _ensure_identity(db, user, "phone", phone)
                if err:
                    return err

            db.commit()

            return jsonify({"ok": True, "status": user.status})

__all__ = ["register_auth_routes"]
