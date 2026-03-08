from __future__ import annotations

def build_auth_helpers(deps):
    # Transitional dependency injection: helpers still depend on
    # legacy names while extraction to service classes continues.
    globals().update(deps)

    def _active_subscription(db, user_id: int) -> Subscription | None:
        sub = (
            db.query(Subscription)
            .filter(Subscription.user_id == user_id)
            .order_by(Subscription.id.desc())
            .first()
        )
        if not sub:
            return None
        status = (sub.status or "").strip().lower()
        if status == "lifetime":
            # Lifetime subscriptions must not have an expiration timestamp.
            if sub.access_until is not None:
                sub.access_until = None
                db.commit()
            return sub
        if status != "active":
            return None
        access_until = _as_utc(sub.access_until)
        if access_until and access_until < utcnow():
            sub.status = "expired"
            db.commit()
            return None
        return sub

    def _latest_subscription(db, user_id: int) -> Subscription | None:
        return (
            db.query(Subscription)
            .filter(Subscription.user_id == user_id)
            .order_by(Subscription.id.desc())
            .first()
        )

    def _extract_connections_limit(user: User) -> int | None:
        profile = user.profile_data if isinstance(user.profile_data, dict) else {}
        raw = profile.get("connections_limit")
        if raw is None:
            raw = profile.get("connection_limit")
        try:
            limit = int(raw) if raw is not None else None
        except (ValueError, TypeError):
            return None
        if limit is None or limit < 0:
            return None
        return limit

    def _serialize_admin_user_overview(db, user: User) -> dict:
        # Keep active/expired status in sync when needed.
        _active_subscription(db, user.id)
        subscription = _latest_subscription(db, user.id)

        accounts = (
            db.query(VpnAccount)
            .filter(VpnAccount.user_id == user.id)
            .order_by(VpnAccount.updated_at.desc(), VpnAccount.id.desc())
            .all()
        )
        active_connections = [a for a in accounts if (a.status or "").lower() == "active"]
        connections_limit = _extract_connections_limit(user)
        available_connections = (
            max(connections_limit - len(active_connections), 0)
            if connections_limit is not None
            else None
        )

        return {
            "user": {
                "id": user.id,
                "telegram_id": user.telegram_id,
                "username": user.username,
                "name": user.name,
                "role": user.role,
            },
            "subscription": None
            if not subscription
            else {
                "id": subscription.id,
                "status": subscription.status,
                "access_until": subscription.access_until.isoformat() if subscription.access_until else None,
                "price_amount": str(subscription.price_amount) if subscription.price_amount is not None else None,
            },
            "connections": {
                "active": len(active_connections),
                "total": len(accounts),
                "limit": connections_limit,
                "available": available_connections,
            },
        }

    def _auth_context(require_role: str | None = None):
        raw_token = request.cookies.get(session_cookie_name)
        if not raw_token:
            return None, (jsonify({"ok": False, "error": "Unauthorized"}), 401)

        token_hash = _token_hash(raw_token)
        with SessionLocal() as db:
            auth_session = db.query(AuthSession).filter(AuthSession.session_token == token_hash).first()
            if not auth_session:
                return None, (jsonify({"ok": False, "error": "Unauthorized"}), 401)
            expires_at = _as_utc(auth_session.expires_at)
            if not expires_at or expires_at < utcnow():
                db.delete(auth_session)
                db.commit()
                return None, (jsonify({"ok": False, "error": "Session expired"}), 401)

            user = db.query(User).filter(User.id == auth_session.user_id).first()
            if not user:
                return None, (jsonify({"ok": False, "error": "Unauthorized"}), 401)
            if not _role_allows(user.role, require_role):
                return None, (jsonify({"ok": False, "error": "Forbidden"}), 403)

            return {
                "user_id": user.id,
                "role": user.role,
                "telegram_id": user.telegram_id,
                "username": user.username,
                "name": user.name,
            }, None

    def _session_csrf_hash(auth_session: AuthSession) -> str:
        session_data = _safe_json(auth_session.init_data)
        value = session_data.get("csrf_hash")
        return value if isinstance(value, str) else ""

    def _verify_csrf_request():
        if request.method not in csrf_protected_methods:
            return None
        if request.path in csrf_exempt_paths:
            return None

        raw_token = request.cookies.get(session_cookie_name)
        if not raw_token:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        token_hash = _token_hash(raw_token)
        request_csrf_token = request.headers.get("X-CSRF-Token", "")
        if not request_csrf_token:
            return jsonify({"ok": False, "error": "CSRF token missing"}), 403

        with SessionLocal() as db:
            auth_session = db.query(AuthSession).filter(AuthSession.session_token == token_hash).first()
            if not auth_session:
                return jsonify({"ok": False, "error": "Unauthorized"}), 401

            expires_at = _as_utc(auth_session.expires_at)
            if not expires_at or expires_at < utcnow():
                db.delete(auth_session)
                db.commit()
                return jsonify({"ok": False, "error": "Session expired"}), 401

            stored_csrf_hash = _session_csrf_hash(auth_session)
            if not stored_csrf_hash:
                return jsonify({"ok": False, "error": "CSRF token is not initialized"}), 403

        if not hmac.compare_digest(_csrf_hash(request_csrf_token), stored_csrf_hash):
            return jsonify({"ok": False, "error": "Invalid CSRF token"}), 403
        return None

    def _new_session(db, user: User, init_data: str):
        raw_token = secrets.token_urlsafe(32)
        raw_csrf_token = secrets.token_urlsafe(32)
        expires_at = utcnow() + timedelta(days=session_ttl_days)
        token_hash = _token_hash(raw_token)
        csrf_hash = _csrf_hash(raw_csrf_token)
        try:
            parsed_init_data = dict(parse_qsl(init_data, keep_blank_values=True)) if init_data else {}
        except ValueError:
            parsed_init_data = {}
        auth_date = None
        raw_auth_date = parsed_init_data.get("auth_date")
        if raw_auth_date is not None:
            try:
                auth_date = int(raw_auth_date)
            except (ValueError, TypeError):
                auth_date = None
        init_data_sha256 = hashlib.sha256(init_data.encode("utf-8")).hexdigest() if init_data else ""
        session_meta = {
            "csrf_hash": csrf_hash,
            "telegram_id": str(user.telegram_id or ""),
            "username": str(user.username or ""),
            "auth_date": auth_date,
            "init_data_sha256": init_data_sha256,
        }

        db.query(AuthSession).filter(AuthSession.expires_at < utcnow()).delete()
        db.add(
            AuthSession(
                user_id=user.id,
                init_data=session_meta,
                session_token=token_hash,
                expires_at=expires_at,
            )
        )
        db.commit()
        return raw_token, raw_csrf_token

    return {
        "_active_subscription": _active_subscription,
        "_latest_subscription": _latest_subscription,
        "_extract_connections_limit": _extract_connections_limit,
        "_serialize_admin_user_overview": _serialize_admin_user_overview,
        "_auth_context": _auth_context,
        "_session_csrf_hash": _session_csrf_hash,
        "_verify_csrf_request": _verify_csrf_request,
        "_new_session": _new_session,
    }

__all__ = ["build_auth_helpers"]
