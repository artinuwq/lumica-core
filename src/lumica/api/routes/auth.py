from __future__ import annotations

def register_auth_routes(app, deps):
    # Transitional dependency injection while handlers are being migrated out
    # of shared app helper closures.
    globals().update(deps)

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

__all__ = ["register_auth_routes"]
