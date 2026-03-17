from __future__ import annotations

from datetime import timedelta
from decimal import Decimal, InvalidOperation

from lumica.domain.models import PanelTemplate, Region, SubscriptionItem, SubscriptionPlan, User

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
        return plan.meta_json if isinstance(plan.meta_json, dict) else {}

    def _plan_item_price_map(plan: SubscriptionPlan) -> dict[tuple[str | None, str], Decimal]:
        meta = _plan_meta(plan)
        raw_items = []
        for key in ("items", "addons", "options"):
            value = meta.get(key)
            if isinstance(value, list):
                raw_items.extend(value)
        prices: dict[tuple[str | None, str], Decimal] = {}
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            code = str(item.get("code") or "").strip()
            if not code:
                continue
            item_type = str(item.get("item_type") or item.get("type") or "").strip().lower()
            item_type = item_type or None
            raw_price = item.get("price") or item.get("amount") or item.get("cost")
            try:
                price = Decimal(str(raw_price)) if raw_price not in (None, "") else None
            except (InvalidOperation, ValueError):
                price = None
            if price is None:
                continue
            prices[(item_type, code)] = price
            if item_type is not None:
                prices[(None, code)] = price
        return prices

    def _resolve_plan(db, payload: dict):
        plan_id_raw = payload.get("plan_id") or payload.get("plan") or payload.get("planId")
        plan_name_raw = payload.get("plan_name") or payload.get("planName") or payload.get("plan_code") or payload.get("planCode")

        plan = None
        if plan_id_raw not in (None, ""):
            try:
                plan_id = int(plan_id_raw)
            except (TypeError, ValueError):
                return None, (jsonify({"ok": False, "error": "plan_id must be an integer"}), 400)
            plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == plan_id).first()
        elif plan_name_raw:
            name = str(plan_name_raw).strip()
            if name:
                plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.name == name).first()

        if not plan:
            return None, (jsonify({"ok": False, "error": "Plan not found"}), 404)
        if not plan.is_active:
            return None, (jsonify({"ok": False, "error": "Plan is inactive"}), 400)
        return plan, None

    def _require_verified_user(db, user_id: int):
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None, (jsonify({"ok": False, "error": "Unauthorized"}), 401)
        status = (user.status or "").strip().lower()
        if status != "verified":
            return None, (jsonify({"ok": False, "error": "Verification required"}), 403)
        return user, None

    def _subscription_duration_months(plan: SubscriptionPlan, payload: dict):
        meta = _plan_meta(plan)
        raw_duration = (
            payload.get("duration_months")
            or payload.get("durationMonths")
            or payload.get("months")
            or payload.get("period_months")
            or payload.get("periodMonths")
            or meta.get("duration_months")
            or meta.get("months")
        )
        duration, err = _int_or_error(raw_duration, "duration_months", default=1, min_value=0)
        if err:
            return None, err
        return duration, None

    def _calculate_subscription_pricing(plan: SubscriptionPlan, payload: dict):
        duration_months, err = _subscription_duration_months(plan, payload)
        if err:
            return None, err
        base_price = plan.base_price or Decimal("0")
        try:
            base_price = Decimal(str(base_price))
        except (InvalidOperation, ValueError):
            base_price = Decimal("0")

        meta = _plan_meta(plan)
        is_lifetime = bool(payload.get("lifetime") or meta.get("lifetime"))
        if duration_months == 0 and is_lifetime is False:
            is_lifetime = True

        items_payload = payload.get("items") or payload.get("addons") or []
        if items_payload in (None, ""):
            items_payload = []
        if not isinstance(items_payload, list):
            return None, (jsonify({"ok": False, "error": "items must be a list"}), 400)

        price_map = _plan_item_price_map(plan)
        items = []
        items_total = Decimal("0")
        for raw_item in items_payload:
            if not isinstance(raw_item, dict):
                return None, (jsonify({"ok": False, "error": "items must contain objects"}), 400)
            code = str(raw_item.get("code") or "").strip()
            if not code:
                return None, (jsonify({"ok": False, "error": "item code is required"}), 400)
            item_type = str(raw_item.get("item_type") or raw_item.get("type") or "addon").strip().lower() or "addon"
            quantity, err = _int_or_error(raw_item.get("quantity"), "item quantity", default=1, min_value=1)
            if err:
                return None, err
            price = price_map.get((item_type, code)) or price_map.get((None, code))
            if price is None:
                return None, (jsonify({"ok": False, "error": f"Unknown price for item {code}"}), 400)
            item_total = price * Decimal(quantity)
            items_total += item_total
            items.append(
                {
                    "item_type": item_type,
                    "code": code,
                    "price": price,
                    "quantity": quantity,
                    "total": item_total,
                    "meta": raw_item.get("meta") if isinstance(raw_item.get("meta"), dict) else {},
                }
            )

        total = base_price if is_lifetime else base_price * Decimal(max(duration_months, 1))
        total += items_total
        pricing = {
            "duration_months": duration_months,
            "is_lifetime": is_lifetime,
            "base_price": base_price,
            "items_total": items_total,
            "total": total,
            "items": items,
        }
        return pricing, None

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
                user = db.query(User).filter(User.telegram_id == telegram_id).first()
                if not user:
                    user = User(telegram_id=telegram_id)
                    db.add(user)
                    db.flush()

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
            db.commit()

            return jsonify({"ok": True, "status": user.status})

__all__ = ["register_auth_routes"]
