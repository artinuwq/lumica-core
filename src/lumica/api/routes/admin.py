from __future__ import annotations

from decimal import Decimal, InvalidOperation

from lumica.domain.models import (
    Application, AuthIdentity, Group, MiniAppLaunch, Panel, Subscription, SubscriptionVpnAccount, User, VpnAccount,
)
from lumica.services import user_provisioning
from lumica.services import subscription_updates
from lumica.services import broadcasts, user_deletion
from lumica.services.operator_events import USER_EVENTS_TOPIC, post_to_topic as post_operator_topic
from lumica.services.panel_labels import server_code
from lumica.services.notification_settings import is_silent
from lumica.services.notifications import send_raw
from lumica.services.user_audit import record_user_event


def register_admin_routes(app, deps):
    # Transitional dependency injection while handlers are being migrated out
    # of shared app helper closures.
    globals().update(deps)

    def _serialize_subscription_plan(plan: SubscriptionPlan) -> dict:
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

    def _serialize_panel_template(template: PanelTemplate) -> dict:
        return {
            "id": template.id,
            "name": template.name,
            "protocol": template.protocol,
            "apply_mode": template.apply_mode,
            "settings": template.settings if isinstance(template.settings, dict) else {},
        }

    @app.post("/api/admin/sync-inbounds")
    def sync_inbounds():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            panels = panel_registry.get_active_panels(db)
            if not panels:
                return jsonify({"ok": False, "error": "No active panels configured"}), 400

            upserted = 0
            stale_disabled = 0
            results: list[dict] = []
            for panel in panels:
                try:
                    provider = panel_registry.get_provider(panel.provider)
                    auth_payload = panel_registry.get_auth_payload(db, panel)
                    items = provider.list_inbounds(panel, auth_payload)

                    seen: set[str] = set()
                    for item in items:
                        row = _sync_single_inbound_from_panel(db, item, panel=panel)
                        upserted += 1
                        seen.add(row.external_inbound_id)

                    stale_rows = (
                        db.query(PanelInbound)
                        .filter(PanelInbound.panel_id == panel.id)
                        .all()
                    )
                    local_stale = 0
                    for stale in stale_rows:
                        if stale.external_inbound_id in seen:
                            continue
                        stale.enabled = 0
                        stale.last_sync_at = utcnow()
                        local_stale += 1
                    stale_disabled += local_stale

                    panel.health_status = "green"
                    panel.last_ok_at = utcnow()
                    panel.error_message = None
                    results.append(
                        {
                            "panel_id": panel.id,
                            "name": panel.name,
                            "ok": True,
                            "upserted": len(seen),
                            "stale_disabled": local_stale,
                        }
                    )
                except Exception as exc:
                    panel_registry.invalidate_panel(panel.id)
                    panel.health_status = "red"
                    panel.error_message = str(exc)[:500]
                    results.append({"panel_id": panel.id, "name": panel.name, "ok": False, "error": str(exc)})

            sync_group_members_from_inbounds(db)
            db.commit()

        return jsonify(
            {
                "ok": True,
                "count": upserted,
                "stale_disabled": stale_disabled,
                "panels": results,
            }
        )

    @app.get("/api/admin/inbounds")
    def list_inbounds():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            rows = (
                db.query(PanelInbound, Panel)
                .join(Panel, Panel.id == PanelInbound.panel_id)
                .order_by(Panel.name.asc(), PanelInbound.id.asc())
                .all()
            )
            inbounds: list[dict] = []
            for inbound, panel in rows:
                panel_inbound_id = None
                try:
                    panel_inbound_id = int(inbound.external_inbound_id)
                except (TypeError, ValueError):
                    panel_inbound_id = None
                inbounds.append(
                    {
                        "id": inbound.id,
                        "panel_inbound_ref_id": inbound.id,
                        "panel_id": panel.id,
                        "panel_name": panel.name,
                        "region": panel.region,
                        "external_inbound_id": inbound.external_inbound_id,
                        "panel_inbound_id": panel_inbound_id,
                        "protocol": inbound.protocol,
                        "port": inbound.port,
                        "remark": inbound.remark,
                        "listen": inbound.listen,
                        "enable": bool(inbound.enabled),
                        "show_in_app": bool(inbound.show_in_app),
                        "updated_at": inbound.updated_at.isoformat() if inbound.updated_at else None,
                        "last_sync_at": inbound.last_sync_at.isoformat() if inbound.last_sync_at else None,
                    }
                )
            return jsonify({"ok": True, "inbounds": inbounds})

    @app.get("/api/admin/settings")
    def admin_settings_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        prefix = (request.args.get("prefix") or "").strip() or None
        with SessionLocal() as db:
            settings = SettingsManager(db).list_settings(prefix=prefix)
            return jsonify({"ok": True, "settings": [_serialize_app_setting(item) for item in settings]})

    @app.get("/api/admin/settings/<setting_key>")
    def admin_settings_get(setting_key: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            manager = SettingsManager(db)
            try:
                item = manager.get_setting(setting_key)
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400

            if not item:
                return jsonify({"ok": False, "error": "Setting not found"}), 404
            return jsonify({"ok": True, "setting": _serialize_app_setting(item)})

    @app.post("/api/admin/settings/<setting_key>")
    def admin_settings_upsert(setting_key: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        if "value" not in body:
            return jsonify({"ok": False, "error": "value is required"}), 400

        description = body.get("description")
        if description is not None and not isinstance(description, str):
            return jsonify({"ok": False, "error": "description must be a string"}), 400

        with SessionLocal() as db:
            manager = SettingsManager(db)
            try:
                item, created = manager.set_setting(
                    setting_key,
                    body.get("value"),
                    description=description,
                )
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400

            db.commit()
            return jsonify({"ok": True, "created": created, "setting": _serialize_app_setting(item)})

    @app.post("/api/admin/settings/<setting_key>/delete")
    def admin_settings_delete(setting_key: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            manager = SettingsManager(db)
            try:
                deleted = manager.delete_setting(setting_key)
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400

            if not deleted:
                return jsonify({"ok": False, "error": "Setting not found"}), 404
            db.commit()
            return jsonify({"ok": True, "deleted": True})

    @app.get("/api/admin/subscription-plans")
    def admin_subscription_plans_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            rows = db.query(SubscriptionPlan).order_by(SubscriptionPlan.id.asc()).all()
            return jsonify({"ok": True, "plans": [_serialize_subscription_plan(row) for row in rows]})

    @app.post("/api/admin/subscription-plans")
    def admin_subscription_plans_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = str(body.get("name") or "").strip()
        if not name:
            return jsonify({"ok": False, "error": "name is required"}), 400

        base_price = None
        if "base_price" in body:
            raw_price = body.get("base_price")
            if raw_price not in (None, ""):
                try:
                    base_price = Decimal(str(raw_price))
                except (InvalidOperation, ValueError):
                    return jsonify({"ok": False, "error": "base_price must be a number"}), 400

        meta = body.get("meta")
        if meta is not None and not isinstance(meta, dict):
            return jsonify({"ok": False, "error": "meta must be an object"}), 400

        with SessionLocal() as db:
            row = SubscriptionPlan(
                name=name,
                is_active=1 if body.get("is_active", True) else 0,
                base_price=base_price,
                meta_json=meta if isinstance(meta, dict) else None,
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "plan": _serialize_subscription_plan(row)})

    @app.post("/api/admin/subscription-plans/<int:plan_id>")
    def admin_subscription_plans_update(plan_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            row = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == plan_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Plan not found"}), 404
            if "name" in body:
                name = str(body.get("name") or "").strip()
                if name:
                    row.name = name
            if "is_active" in body:
                row.is_active = 1 if body.get("is_active") else 0
            if "base_price" in body:
                raw_price = body.get("base_price")
                if raw_price in (None, ""):
                    row.base_price = None
                else:
                    try:
                        row.base_price = Decimal(str(raw_price))
                    except (InvalidOperation, ValueError):
                        return jsonify({"ok": False, "error": "base_price must be a number"}), 400
            if "meta" in body:
                meta = body.get("meta")
                if meta is None:
                    row.meta_json = None
                elif not isinstance(meta, dict):
                    return jsonify({"ok": False, "error": "meta must be an object"}), 400
                else:
                    row.meta_json = meta
            db.commit()
            return jsonify({"ok": True, "plan": _serialize_subscription_plan(row)})

    @app.post("/api/admin/subscription-plans/<int:plan_id>/delete")
    def admin_subscription_plans_delete(plan_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            row = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == plan_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Plan not found"}), 404
            deleted = _serialize_subscription_plan(row)
            db.delete(row)
            db.commit()
            return jsonify({"ok": True, "deleted": deleted})

    @app.get("/api/admin/regions")
    def admin_regions_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            rows = db.query(Region).order_by(Region.name.asc(), Region.id.asc()).all()
            return jsonify({"ok": True, "regions": [_serialize_region(row) for row in rows]})

    @app.post("/api/admin/regions")
    def admin_regions_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        code = str(body.get("code") or "").strip().upper()
        name = str(body.get("name") or "").strip()
        if not code or not name:
            return jsonify({"ok": False, "error": "code and name are required"}), 400
        with SessionLocal() as db:
            existing = db.query(Region).filter(Region.code == code).first()
            if existing:
                return jsonify({"ok": False, "error": "Region code already exists"}), 409
            row = Region(
                code=code[:16],
                name=name[:64],
                is_active=1 if body.get("is_active", True) else 0,
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "region": _serialize_region(row)})

    @app.post("/api/admin/regions/<int:region_id>")
    def admin_regions_update(region_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            row = db.query(Region).filter(Region.id == region_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Region not found"}), 404
            if "code" in body:
                code = str(body.get("code") or "").strip().upper()
                if code and code != row.code:
                    existing = db.query(Region).filter(Region.code == code).first()
                    if existing:
                        return jsonify({"ok": False, "error": "Region code already exists"}), 409
                    row.code = code[:16]
            if "name" in body:
                name = str(body.get("name") or "").strip()
                if name:
                    row.name = name[:64]
            if "is_active" in body:
                row.is_active = 1 if body.get("is_active") else 0
            db.commit()
            return jsonify({"ok": True, "region": _serialize_region(row)})

    @app.post("/api/admin/regions/<int:region_id>/delete")
    def admin_regions_delete(region_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            row = db.query(Region).filter(Region.id == region_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Region not found"}), 404
            deleted = _serialize_region(row)
            db.delete(row)
            db.commit()
            return jsonify({"ok": True, "deleted": deleted})

    @app.get("/api/admin/panel-templates")
    def admin_panel_templates_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            rows = db.query(PanelTemplate).order_by(PanelTemplate.name.asc(), PanelTemplate.id.asc()).all()
            return jsonify({"ok": True, "templates": [_serialize_panel_template(row) for row in rows]})

    @app.post("/api/admin/panel-templates")
    def admin_panel_templates_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = str(body.get("name") or "").strip()
        protocol = str(body.get("protocol") or "").strip().lower()
        if not name or not protocol:
            return jsonify({"ok": False, "error": "name and protocol are required"}), 400
        settings = body.get("settings")
        if settings is not None and not isinstance(settings, dict):
            return jsonify({"ok": False, "error": "settings must be an object"}), 400
        apply_mode = str(body.get("apply_mode") or body.get("applyMode") or "").strip()
        with SessionLocal() as db:
            row = PanelTemplate(
                name=name[:120],
                protocol=protocol[:32],
                settings=settings if isinstance(settings, dict) else None,
                apply_mode=apply_mode[:16] or "only_auto",
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "template": _serialize_panel_template(row)})

    @app.post("/api/admin/panel-templates/<int:template_id>")
    def admin_panel_templates_update(template_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            row = db.query(PanelTemplate).filter(PanelTemplate.id == template_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Template not found"}), 404
            if "name" in body:
                name = str(body.get("name") or "").strip()
                if name:
                    row.name = name[:120]
            if "protocol" in body:
                protocol = str(body.get("protocol") or "").strip().lower()
                if protocol:
                    row.protocol = protocol[:32]
            if "apply_mode" in body or "applyMode" in body:
                apply_mode = str(body.get("apply_mode") or body.get("applyMode") or "").strip()
                if apply_mode:
                    row.apply_mode = apply_mode[:16]
            if "settings" in body:
                settings = body.get("settings")
                if settings is None:
                    row.settings = None
                elif not isinstance(settings, dict):
                    return jsonify({"ok": False, "error": "settings must be an object"}), 400
                else:
                    row.settings = settings
            db.commit()
            return jsonify({"ok": True, "template": _serialize_panel_template(row)})

    @app.post("/api/admin/panel-templates/<int:template_id>/delete")
    def admin_panel_templates_delete(template_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            row = db.query(PanelTemplate).filter(PanelTemplate.id == template_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Template not found"}), 404
            deleted = _serialize_panel_template(row)
            db.delete(row)
            db.commit()
            return jsonify({"ok": True, "deleted": deleted})

    @app.post("/api/admin/inbounds/<int:panel_inbound_ref_id>/visibility")
    def admin_inbound_visibility(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        if "show_in_app" not in body:
            return jsonify({"ok": False, "error": "show_in_app is required"}), 400

        with SessionLocal() as db:
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not panel_inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404

            next_visibility = 1 if body.get("show_in_app") else 0
            panel_inbound.show_in_app = next_visibility
            db.commit()

            panel_inbound_id = None
            try:
                panel_inbound_id = int(panel_inbound.external_inbound_id)
            except (TypeError, ValueError):
                panel_inbound_id = None
            return jsonify(
                {
                    "ok": True,
                    "inbound": {
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": panel_inbound.id,
                        "protocol": panel_inbound.protocol,
                        "remark": panel_inbound.remark,
                        "port": panel_inbound.port,
                        "enable": bool(panel_inbound.enabled),
                        "show_in_app": bool(next_visibility),
                    },
                }
            )

    @app.get("/api/admin/users")
    def admin_users():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        # В списке клиентов - только те, кого уже добавили с подпиской (есть
        # не-черновая подписка или админ задал тип подписки). Те, кто просто
        # открыл бота, сюда не попадают: их можно выбрать через /users/known.
        with SessionLocal() as db:
            latest_subscription: dict[int, Subscription] = {}
            for sub in (
                db.query(Subscription)
                .filter(Subscription.status != "draft")
                .order_by(Subscription.id.asc())
                .all()
            ):
                latest_subscription[sub.user_id] = sub

            opened_launch_ids = {
                row.user_id
                for row in db.query(MiniAppLaunch.user_id)
                .filter(MiniAppLaunch.status == "opened")
                .distinct()
                .all()
            }
            group_admins = {row.id: row.admin_user_id for row in db.query(Group).all()}
            panels_by_id = {panel.id: panel for panel in db.query(Panel).all()}
            servers_by_user: dict[int, dict[str, dict]] = {}
            for account_user_id, account_meta, account_status in db.query(
                VpnAccount.user_id, VpnAccount.meta_json, VpnAccount.status
            ).all():
                panel = panels_by_id.get(account_meta.get("panel_id")) if isinstance(account_meta, dict) else None
                if panel is None or (account_status or "").lower() != "active":
                    continue
                servers_by_user.setdefault(account_user_id, {})[panel.id] = {
                    "id": panel.id,
                    "code": server_code(panel),
                    "name": panel.name,
                }
            users: list[dict] = []
            for u in db.query(User).order_by(User.id.asc()).all():
                profile = u.profile_data if isinstance(u.profile_data, dict) else {}
                subscription_type = profile.get("subscription_type")
                sub = latest_subscription.get(u.id)
                opened_launch = u.id in opened_launch_ids
                if sub is None and not subscription_type and not opened_launch:
                    continue
                users.append(
                    {
                        "id": u.id,
                        "telegram_id": u.telegram_id,
                        "username": u.username,
                        "name": u.name,
                        "role": u.role,
                        "group_id": u.group_id,
                        "subscription_type": subscription_type or "personal",
                        "subscription_status": sub.status if sub else None,
                        # Данные для фильтров списка клиентов.
                        "is_group_admin": bool(u.group_id and group_admins.get(u.group_id) == u.id),
                        "is_frozen": bool(sub.is_frozen) if sub else False,
                        "price_amount": str(sub.price_amount) if sub and sub.price_amount is not None else None,
                        "billing_day": sub.billing_day if sub else None,
                        "access_until": sub.access_until.isoformat() if sub and sub.access_until else None,
                        "servers": list(servers_by_user.get(u.id, {}).values()),
                    }
                )
            return jsonify({"ok": True, "users": users})

    @app.get("/api/admin/users/known")
    def admin_known_users():
        """Все, кто хотя бы раз открывал мини-приложение или писал боту (подал
        заявку) - для выбора в «Новый пользователь -> Уже есть».

        Раньше брались только строки mini_app_launches, но их нигде не создают,
        поэтому список всегда был пустым. Мини-приложение оставляет следы в
        auth_identities (telegram) и в profile_data (last_seen/visit_count), бот -
        в applications. Заранее созданные админом записи, в которые человек ещё
        не заходил, сюда не попадают."""
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            app_user_ids: set[int] = set()
            for (uid,) in db.query(MiniAppLaunch.user_id).filter(MiniAppLaunch.user_id.isnot(None)).distinct():
                app_user_ids.add(uid)
            for (uid,) in db.query(AuthIdentity.user_id).filter(AuthIdentity.provider == "telegram").distinct():
                app_user_ids.add(uid)
            bot_user_ids = {uid for (uid,) in db.query(Application.user_id).distinct() if uid is not None}

            items: list[dict] = []
            for user in db.query(User).all():
                profile = user.profile_data if isinstance(user.profile_data, dict) else {}
                opened_app = user.id in app_user_ids or bool(profile.get("last_seen"))
                wrote_bot = user.id in bot_user_ids
                if not (opened_app or wrote_bot):
                    continue
                items.append(
                    {
                        "id": user.id,
                        "telegram_id": user.telegram_id,
                        "username": user.username,
                        "name": user.name,
                        "source": "app" if opened_app else "bot",
                    }
                )
            items.sort(key=lambda row: (str(row["name"] or row["username"] or "").lower(), row["id"]))
            return jsonify({"ok": True, "users": items})

    @app.post("/api/admin/users")
    def admin_users_create():
        """Ручное создание пользователя ДО его первого захода в бот (по
        username или телефону) - см. services/user_provisioning.py.
        Когда человек напишет боту, запись свяжется с его telegram_id
        автоматически, дубликат не создастся."""
        auth, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            raw_username = body.get("username")
            if raw_username not in (None, "") and not str(raw_username).strip().startswith("@"):
                return jsonify({"ok": False, "error": "username должен начинаться с @"}), 400
            try:
                user = user_provisioning.create_preprovisioned_user(
                    db,
                    telegram_id=body.get("telegram_id"),
                    username=body.get("username"),
                    phone=body.get("phone"),
                    name=body.get("name"),
                    role=str(body.get("role") or "user").strip().lower(),
                    allow_placeholder=bool(body.get("allow_placeholder", False)),
                )
                payload_err = _apply_admin_subscription_payload(db, user, body)
                if payload_err:
                    db.rollback()
                    return payload_err
                record_user_event(
                    db,
                    actor_user_id=auth["user_id"],
                    subject_user_id=user.id,
                    action="user_created",
                    changes={
                        "telegram_id": user.telegram_id,
                        "username": user.username,
                        "name": user.name,
                        "subscription_type": body.get("subscription_type", "personal"),
                    },
                )
                db.commit()
            except user_provisioning.UserProvisioningError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return (
                jsonify(
                    {
                        "ok": True,
                        "user": {
                            "id": user.id,
                            "telegram_id": user.telegram_id,
                            "username": user.username,
                            "phone": user.phone,
                            "name": user.name,
                            "role": user.role,
                            "group_id": user.group_id,
                        },
                    }
                ),
                201,
            )

    @app.post("/api/admin/users/<int:user_id>/role")
    def admin_user_role_update(user_id: int):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        role_raw = body.get("role")
        if role_raw is None:
            return jsonify({"ok": False, "error": "role is required"}), 400

        role = str(role_raw).strip().lower()
        if role not in ROLE_PRIORITY:
            return jsonify({"ok": False, "error": "role is invalid"}), 400

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            previous_role = user.role
            user.role = role
            record_user_event(
                db,
                actor_user_id=auth["user_id"],
                subject_user_id=user.id,
                action="user_role_changed",
                changes={"from": previous_role, "to": role},
            )
            db.commit()
            db.refresh(user)
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
                }
            )

    @app.get("/api/admin/users/<int:user_id>/bindings")
    def admin_user_bindings(user_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            accounts = (
                db.query(VpnAccount)
                .filter(VpnAccount.user_id == user_id)
                .order_by(VpnAccount.updated_at.desc(), VpnAccount.id.desc())
                .all()
            )

            inbound_ref_ids = {a.panel_inbound_ref_id for a in accounts if a.panel_inbound_ref_id is not None}
            panel_inbounds_by_ref: dict[int, PanelInbound] = {}
            panels_by_id: dict[str, Panel] = {}
            if inbound_ref_ids:
                rows = db.query(PanelInbound).filter(PanelInbound.id.in_(inbound_ref_ids)).all()
                panel_inbounds_by_ref = {row.id: row for row in rows}
                panel_ids = {row.panel_id for row in rows}
                if panel_ids:
                    panel_rows = db.query(Panel).filter(Panel.id.in_(panel_ids)).all()
                    panels_by_id = {row.id: row for row in panel_rows}

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
                    "bindings": [
                        {
                            "id": a.id,
                            "protocol": a.protocol,
                            "panel_inbound_id": (
                                int(panel_inbounds_by_ref[a.panel_inbound_ref_id].external_inbound_id)
                                if (
                                    a.panel_inbound_ref_id in panel_inbounds_by_ref
                                    and str(panel_inbounds_by_ref[a.panel_inbound_ref_id].external_inbound_id).isdigit()
                                )
                                else None
                            ),
                            "panel_inbound_ref_id": a.panel_inbound_ref_id,
                            "panel_id": (
                                panel_inbounds_by_ref[a.panel_inbound_ref_id].panel_id
                                if a.panel_inbound_ref_id in panel_inbounds_by_ref
                                else None
                            ),
                            "panel_name": (
                                panels_by_id[panel_inbounds_by_ref[a.panel_inbound_ref_id].panel_id].name
                                if (
                                    a.panel_inbound_ref_id in panel_inbounds_by_ref
                                    and panel_inbounds_by_ref[a.panel_inbound_ref_id].panel_id in panels_by_id
                                )
                                else None
                            ),
                            "inbound_remark": (
                                panel_inbounds_by_ref[a.panel_inbound_ref_id].remark
                                if a.panel_inbound_ref_id in panel_inbounds_by_ref
                                else None
                            ),
                            "inbound_port": (
                                panel_inbounds_by_ref[a.panel_inbound_ref_id].port
                                if a.panel_inbound_ref_id in panel_inbounds_by_ref
                                else None
                            ),
                            "external_inbound_id": (
                                panel_inbounds_by_ref[a.panel_inbound_ref_id].external_inbound_id
                                if a.panel_inbound_ref_id in panel_inbounds_by_ref
                                else None
                            ),
                            "identifier": a.identifier,
                            "label": a.label,
                            "status": a.status,
                            "sub_id": (
                                (a.meta_json or {}).get("sub_id")
                                if isinstance(a.meta_json, dict)
                                else None
                            ),
                            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
                        }
                        for a in accounts
                    ],
                }
            )

    @app.get("/api/admin/users/<int:user_id>/overview")
    def admin_user_overview(user_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            return jsonify({"ok": True, "overview": _serialize_admin_user_overview(db, user)})

    @app.post("/api/admin/users/<int:user_id>/subscription")
    def admin_user_subscription_update(user_id: int):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            before_snapshot = subscription_updates.snapshot(_admin_latest_subscription(db, user.id))
            payload_err = _apply_admin_subscription_payload(db, user, body)
            if payload_err:
                return payload_err
            after_snapshot = subscription_updates.snapshot(_admin_latest_subscription(db, user.id))

            changes = {
                key: ("updated" if key == "billing_details" else body.get(key))
                for key in (
                    "status", "price_amount", "access_until", "billing_day", "billing_details",
                    "notes", "subscription_type", "vpn_account_ids",
                )
                if key in body
            }
            record_user_event(
                db,
                actor_user_id=auth["user_id"],
                subject_user_id=user.id,
                action="subscription_updated",
                changes=changes,
            )

            db.commit()
            db.refresh(user)
            subscription_updates.notify_subscription_updated(db, user, before_snapshot, after_snapshot)
            return jsonify({"ok": True, "overview": _serialize_admin_user_overview(db, user)})

    @app.get("/api/admin/users/by-telegram/<telegram_id>/overview")
    def admin_user_overview_by_telegram(telegram_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        telegram_id = str(telegram_id or "").strip()
        if not telegram_id.isdigit():
            return jsonify({"ok": False, "error": "telegram_id must be numeric"}), 400

        with SessionLocal() as db:
            user = db.query(User).filter(User.telegram_id == telegram_id).first()
            if not user:
                return jsonify({"ok": True, "exists": False, "overview": None})
            return jsonify({"ok": True, "exists": True, "overview": _serialize_admin_user_overview(db, user)})

    @app.post("/api/admin/users/by-telegram/subscription")
    def admin_user_subscription_update_by_telegram():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        telegram_id = str(body.get("telegram_id") or "").strip()
        if not telegram_id or not telegram_id.isdigit():
            return jsonify({"ok": False, "error": "telegram_id must be numeric"}), 400

        with SessionLocal() as db:
            user, created_user = _get_or_create_user_by_telegram_id(db, telegram_id)
            payload_err = _apply_admin_subscription_payload(db, user, body)
            if payload_err:
                return payload_err

            db.commit()
            db.refresh(user)
            return jsonify(
                {
                    "ok": True,
                    "created_user": created_user,
                    "user_id": user.id,
                    "overview": _serialize_admin_user_overview(db, user),
                }
            )

    @app.get("/api/admin/inbounds/<int:panel_inbound_ref_id>/clients")
    def admin_inbound_clients(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not panel_inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404
            clients = extract_clients_from_panel_inbound(panel_inbound)
            panel_inbound_id = None
            try:
                panel_inbound_id = int(panel_inbound.external_inbound_id)
            except (TypeError, ValueError):
                panel_inbound_id = None
            return jsonify(
                {
                    "ok": True,
                    "panel_inbound_id": panel_inbound_id,
                    "panel_inbound_ref_id": panel_inbound.id,
                    "protocol": panel_inbound.protocol,
                    "clients": clients,
                }
            )

    @app.post("/api/admin/inbounds/<int:panel_inbound_ref_id>/clients")
    def admin_inbound_clients_create(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        label = str(body.get("label") or body.get("email") or "").strip()
        if not label:
            return jsonify({"ok": False, "error": "label is required"}), 400
        label = label[:64]

        def _as_non_negative_int(value, default=0):
            if value in (None, ""):
                return default
            try:
                out = int(value)
            except (TypeError, ValueError):
                raise ValueError("must be an integer")
            if out < 0:
                raise ValueError("must be >= 0")
            return out

        try:
            limit_ip = _as_non_negative_int(body.get("limit_ip"), default=0)
            total_gb = _as_non_negative_int(body.get("total_gb"), default=0)
            expiry_days = _as_non_negative_int(body.get("expiry_days"), default=0)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        flow = str(body.get("flow") or "xtls-rprx-vision").strip() or "xtls-rprx-vision"
        client_id = str(uuid4())
        sub_id = str(body.get("sub_id") or _generate_panel_sub_id()).strip()[:32] or _generate_panel_sub_id()
        expiry_time_ms = 0
        if expiry_days > 0:
            expiry_time_ms = int((utcnow() + timedelta(days=expiry_days)).timestamp() * 1000)
        total_bytes = int(total_gb) * 1024 * 1024 * 1024

        with SessionLocal() as db:
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not panel_inbound:
                return jsonify({"ok": False, "error": "Inbound not found"}), 404

            effective_protocol = str(panel_inbound.protocol or "").strip().lower()
            if effective_protocol != "vless":
                return jsonify({"ok": False, "error": "Adding new clients is currently supported only for VLESS inbounds"}), 400

            existing = extract_clients_from_panel_inbound(panel_inbound)
            existing_labels = {str(item.get("label") or "").strip().lower() for item in existing}
            if label.lower() in existing_labels:
                return jsonify({"ok": False, "error": "Client with this label already exists"}), 409

            client_payload = {
                "id": client_id,
                "email": label,
                "flow": flow,
                "limitIp": limit_ip,
                "totalGB": total_bytes,
                "expiryTime": expiry_time_ms,
                "enable": True,
                "tgId": 0,
                "subId": sub_id,
                "reset": 0,
            }

            panel_result = None
            refresh_warning = None
            panel = db.query(Panel).filter(Panel.id == panel_inbound.panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found for inbound"}), 404
            try:
                provider = panel_registry.get_provider(panel.provider)
                auth_payload = panel_registry.get_auth_payload(db, panel)
                panel_result = provider.create_client(panel, panel_inbound, client_payload, auth_payload)
            except Exception as exc:
                app.logger.exception("add inbound client failed")
                return jsonify({"ok": False, "error": str(exc)}), 502

            try:
                provider = panel_registry.get_provider(panel.provider)
                auth_payload = panel_registry.get_auth_payload(db, panel)
                panel_items = provider.list_inbounds(panel, auth_payload)
                panel_item = next(
                    (item for item in panel_items if str(item.get("id")) == str(panel_inbound.external_inbound_id)),
                    None,
                )
                if panel_item:
                    panel_inbound = _sync_single_inbound_from_panel(db, panel_item, panel=panel)
                    db.commit()
                else:
                    refresh_warning = "Client created in panel, but inbound was not found during refresh."
            except Exception as exc:
                refresh_warning = f"Client created in panel, but local refresh failed: {exc}"
                app.logger.warning("refresh inbound after add-client failed: %s", exc)

            clients = extract_clients_from_panel_inbound(panel_inbound)
            created = next((item for item in clients if str(item.get("identifier")) == client_id), None)
            if not created:
                created = {
                    "identifier": client_id,
                    "label": label,
                    "sub_id": sub_id,
                    "protocol": effective_protocol,
                }
                clients = [created, *clients]

            panel_inbound_id = None
            try:
                panel_inbound_id = int(panel_inbound.external_inbound_id)
            except (TypeError, ValueError):
                panel_inbound_id = None
            return jsonify(
                {
                    "ok": True,
                    "panel_inbound_id": panel_inbound_id,
                    "panel_inbound_ref_id": panel_inbound.id,
                    "protocol": effective_protocol,
                    "created_client": created,
                    "clients": clients,
                    "panel_result": panel_result,
                    "warning": refresh_warning,
                }
            )

    @app.post("/api/admin/bind-client")
    def admin_bind_client():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        user_id = body.get("user_id")
        panel_inbound_ref_id_raw = body.get("panel_inbound_ref_id")
        identifier = (body.get("client_identifier") or "").strip()
        protocol = _normalize_account_protocol(body.get("protocol"))
        label = body.get("label")
        secret = body.get("secret")
        sub_id = body.get("sub_id")

        if not user_id or panel_inbound_ref_id_raw in (None, "") or not identifier:
            return jsonify({"ok": False, "error": "user_id, panel_inbound_ref_id, client_identifier are required"}), 400
        if protocol not in {"vless", "mixed"}:
            return jsonify({"ok": False, "error": "protocol must be vless or mixed"}), 400

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == int(user_id)).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            try:
                panel_inbound_ref_id = int(panel_inbound_ref_id_raw)
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "panel_inbound_ref_id must be an integer"}), 400
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not panel_inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404

            account = _upsert_vpn_account(
                db,
                user_id=user.id,
                panel_inbound_ref_id=panel_inbound_ref_id,
                protocol=protocol,
                identifier=identifier,
                label=label,
                secret=secret,
                sub_id=sub_id,
            )
            subscription_id_raw = body.get("subscription_id")
            if subscription_id_raw not in (None, ""):
                try:
                    subscription_id = int(subscription_id_raw)
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error": "subscription_id must be an integer"}), 400
                subscription = db.query(Subscription).filter(
                    Subscription.id == subscription_id,
                    Subscription.user_id == user.id,
                ).first()
                if not subscription:
                    db.rollback()
                    return jsonify({"ok": False, "error": "subscription does not belong to this user"}), 400
            else:
                subscription = (
                    db.query(Subscription)
                    .filter(Subscription.user_id == user.id)
                    .order_by(Subscription.id.desc())
                    .first()
                )
            if subscription:
                linked = db.query(SubscriptionVpnAccount).filter(
                    SubscriptionVpnAccount.subscription_id == subscription.id,
                    SubscriptionVpnAccount.vpn_account_id == account.id,
                ).first()
                if not linked:
                    db.add(SubscriptionVpnAccount(subscription_id=subscription.id, vpn_account_id=account.id))
            record_user_event(
                db,
                actor_user_id=auth["user_id"],
                subject_user_id=user.id,
                action="vpn_account_bound",
                changes={
                    "vpn_account_id": account.id,
                    "panel_inbound_ref_id": panel_inbound_ref_id,
                    "protocol": protocol,
                    "label": account.label,
                    "subscription_id": subscription.id if subscription else None,
                },
            )
            db.commit()

            panel_inbound_id = None
            try:
                panel_inbound_id = int(panel_inbound.external_inbound_id)
            except (TypeError, ValueError):
                panel_inbound_id = None
            return jsonify(
                {
                    "ok": True,
                    "account": {
                        "id": account.id,
                        "user_id": account.user_id,
                        "protocol": account.protocol,
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": account.panel_inbound_ref_id,
                        "identifier": account.identifier,
                        "label": account.label,
                        "status": account.status,
                    },
                }
            )

    @app.get("/api/admin/pending-bindings")
    def admin_pending_bindings():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        telegram_id = (request.args.get("telegram_id") or "").strip()
        status = (request.args.get("status") or "").strip().lower()
        limit_raw = request.args.get("limit")
        try:
            limit = int(limit_raw) if limit_raw not in (None, "") else 200
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "limit must be an integer"}), 400
        limit = max(1, min(limit, 500))

        with SessionLocal() as db:
            query = db.query(PendingBinding).order_by(PendingBinding.id.desc())
            if telegram_id:
                query = query.filter(PendingBinding.telegram_id == telegram_id)
            if status:
                query = query.filter(PendingBinding.status == status)

            rows = query.limit(limit).all()
            return jsonify(
                {
                    "ok": True,
                    "pending_bindings": [_serialize_pending_binding(db, row) for row in rows],
                }
            )

    @app.post("/api/admin/pending-bindings")
    def admin_pending_bindings_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        telegram_id = str(body.get("telegram_id") or "").strip()
        panel_inbound_ref_id_raw = body.get("panel_inbound_ref_id")
        identifier = str(body.get("client_identifier") or "").strip()
        protocol = _normalize_account_protocol(body.get("protocol"))
        label = body.get("label")
        secret = body.get("secret")
        sub_id = body.get("sub_id")

        if not telegram_id or not telegram_id.isdigit():
            return jsonify({"ok": False, "error": "telegram_id must be numeric"}), 400
        if panel_inbound_ref_id_raw in (None, "") or not identifier:
            return jsonify({"ok": False, "error": "panel_inbound_ref_id and client_identifier are required"}), 400
        if protocol not in {"vless", "mixed"}:
            return jsonify({"ok": False, "error": "protocol must be vless or mixed"}), 400
        try:
            panel_inbound_ref_id = int(panel_inbound_ref_id_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "panel_inbound_ref_id must be an integer"}), 400

        with SessionLocal() as db:
            panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not panel_inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            try:
                panel_inbound_id = int(panel_inbound.external_inbound_id)
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "Panel inbound external id is not numeric"}), 400

            existing = (
                db.query(PendingBinding)
                .filter(
                    PendingBinding.telegram_id == telegram_id,
                    PendingBinding.protocol == protocol,
                    PendingBinding.panel_inbound_ref_id == panel_inbound_ref_id,
                    PendingBinding.identifier == identifier,
                    PendingBinding.status == "pending",
                )
                .order_by(PendingBinding.id.desc())
                .first()
            )
            if existing:
                meta = existing.meta_json if isinstance(existing.meta_json, dict) else {}
                if sub_id:
                    meta["sub_id"] = str(sub_id)
                existing.label = label or existing.label or identifier
                existing.secret = secret if protocol == "mixed" else None
                existing.meta_json = meta
                existing.panel_inbound_ref_id = panel_inbound_ref_id
                existing.panel_inbound_id = panel_inbound_id
                db.commit()
                return jsonify(
                    {
                        "ok": True,
                        "deduplicated": True,
                        "pending_binding": _serialize_pending_binding(db, existing),
                    }
                )

            row = PendingBinding(
                telegram_id=telegram_id,
                protocol=protocol,
                panel_inbound_id=panel_inbound_id,
                panel_inbound_ref_id=panel_inbound_ref_id,
                identifier=identifier,
                label=label or identifier,
                secret=secret if protocol == "mixed" else None,
                meta_json={"sub_id": str(sub_id)} if sub_id else {},
                status="pending",
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "pending_binding": _serialize_pending_binding(db, row)})

    @app.post("/api/admin/pending-bindings/<int:pending_id>/cancel")
    def admin_pending_binding_cancel(pending_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        with SessionLocal() as db:
            row = db.query(PendingBinding).filter(PendingBinding.id == pending_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Pending binding not found"}), 404
            if row.status != "pending":
                return jsonify({"ok": False, "error": "Only pending bindings can be canceled"}), 400

            row.status = "canceled"
            db.commit()
            return jsonify({"ok": True, "pending_binding": _serialize_pending_binding(db, row)})

    @app.post("/api/admin/unbind-client")
    def admin_unbind_client():
        _, err = _auth_context(require_role="admin")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        binding_id = body.get("binding_id")
        if not binding_id:
            return jsonify({"ok": False, "error": "binding_id is required"}), 400

        with SessionLocal() as db:
            account = db.query(VpnAccount).filter(VpnAccount.id == int(binding_id)).first()
            if not account:
                return jsonify({"ok": False, "error": "Binding not found"}), 404

            panel_inbound_id = None
            if account.panel_inbound_ref_id:
                panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == account.panel_inbound_ref_id).first()
                if panel_inbound:
                    try:
                        panel_inbound_id = int(panel_inbound.external_inbound_id)
                    except (TypeError, ValueError):
                        panel_inbound_id = None
            deleted = {
                "id": account.id,
                "user_id": account.user_id,
                "protocol": account.protocol,
                "panel_inbound_id": panel_inbound_id,
                "panel_inbound_ref_id": account.panel_inbound_ref_id,
                "identifier": account.identifier,
                "label": account.label,
            }
            db.delete(account)
            db.commit()

            return jsonify({"ok": True, "deleted": deleted})

    @app.get("/api/admin/panel-clients")
    def admin_panel_clients_list():
        """Список клиентов панели (Clients API) для выбора при привязке к
        пользователю бота. Возвращает клиентов всех активных панелей, помечая
        уже привязанных (есть VpnAccount с identifier == email)."""
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        # ?panel_id=... - клиенты одного сервера (в том числе неактивного).
        panel_id_filter = str(request.args.get("panel_id") or "").strip()
        with SessionLocal() as db:
            if panel_id_filter:
                panels = db.query(Panel).filter(Panel.id == panel_id_filter).all()
            else:
                panels = db.query(Panel).filter(Panel.is_active == 1).all()
            if not panels:
                return jsonify({"ok": True, "clients": [], "errors": []})

            bound_identifiers: set[str] = {
                str(row.identifier).strip().lower()
                for row in db.query(VpnAccount.identifier).distinct()
                if row.identifier
            }

            clients: list[dict] = []
            errors: list[dict] = []
            for panel in panels:
                try:
                    provider = panel_registry.get_provider(panel.provider)
                    auth_payload = panel_registry.get_auth_payload(db, panel)
                    rows = provider.list_panel_clients(panel, auth_payload)
                except Exception as exc:
                    errors.append({"panel_id": panel.id, "panel_name": panel.name, "error": str(exc)})
                    continue
                for row in rows:
                    email = str(row.get("email") or "").strip()
                    if not email:
                        continue
                    clients.append(
                        {
                            **row,
                            "panel_id": panel.id,
                            "panel_name": panel.name,
                            "region": panel.region,
                            "bound": email.lower() in bound_identifiers,
                        }
                    )
            return jsonify({"ok": True, "clients": clients, "errors": errors})

    @app.post("/api/admin/users/<int:user_id>/panel-client")
    def admin_user_bind_panel_client(user_id: int):
        """Привязывает уже созданного клиента панели (Clients API) к
        пользователю бота. Тело: {panel_id, email}. Делает get_client(email),
        создаёт VpnAccount (identifier = email клиента) и записывает в панель
        tgId пользователя, чтобы связь читалась с обеих сторон."""
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        panel_id = str(body.get("panel_id") or "").strip()
        email = str(body.get("email") or "").strip()
        set_tg_id = bool(body.get("set_tg_id", True))
        if not panel_id or not email:
            return jsonify({"ok": False, "error": "panel_id and email are required"}), 400

        with SessionLocal() as db:
            user = db.query(User).filter(User.id == int(user_id)).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            panel = db.query(Panel).filter(Panel.id == panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404

            provider = panel_registry.get_provider(panel.provider)
            auth_payload = panel_registry.get_auth_payload(db, panel)
            try:
                client = provider.get_panel_client(panel, auth_payload, email)
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 502
            if not client or not client.get("email"):
                # Клиент не найден через get API. Пытаемся создать его в панели,
                # используя inbound_ids/sub_id из тела запроса или из списка
                # клиентов панели (если клиент уже существует, но get API его не вернул).
                inbound_ids = body.get("inbound_ids") or []
                if isinstance(inbound_ids, str):
                    try:
                        inbound_ids = [int(x.strip()) for x in inbound_ids.split(",") if x.strip()]
                    except (TypeError, ValueError):
                        inbound_ids = []
                inbound_ids = [int(i) for i in inbound_ids if str(i).strip().isdigit()]
                sub_id = body.get("sub_id") or None

                if not inbound_ids:
                    try:
                        panel_clients = provider.list_panel_clients(panel, auth_payload)
                        for pc in panel_clients:
                            if str(pc.get("email") or "").strip().lower() == email.lower():
                                inbound_ids = pc.get("inbound_ids") or []
                                sub_id = pc.get("sub_id") or sub_id
                                break
                    except Exception:
                        pass

                if not inbound_ids:
                    return jsonify({"ok": False, "error": "Client not found in panel"}), 404

                client_payload = {
                    "email": email,
                    "subId": sub_id,
                    "enable": True,
                    "limitIp": 0,
                    "totalGB": 0,
                    "expiryTime": 0,
                    "tgId": 0,
                    "reset": 0,
                    "comment": email,
                }
                try:
                    provider.create_panel_client(panel, auth_payload, client_payload, inbound_ids)
                except Exception as exc:
                    return jsonify(
                        {"ok": False, "error": f"Failed to create client in panel: {exc}"}
                    ), 502

                client = provider.get_panel_client(panel, auth_payload, email)
                if not client or not client.get("email"):
                    return jsonify({"ok": False, "error": "Client not found in panel"}), 404

            occupied = (
                db.query(VpnAccount)
                .filter(VpnAccount.identifier == email)
                .filter(VpnAccount.user_id != user.id)
                .first()
            )
            if occupied is not None:
                return jsonify(
                    {"ok": False, "error": "Client already bound to another user"}
                ), 409

            warning = None
            if set_tg_id and user.telegram_id:
                try:
                    tg_numeric = int(str(user.telegram_id).strip())
                    merged = dict(client.get("raw") or {})
                    merged.pop("traffic", None)
                    merged.pop("inboundIds", None)
                    merged["email"] = client["email"]
                    merged["tgId"] = tg_numeric
                    provider.update_panel_client(
                        panel,
                        auth_payload,
                        client["email"],
                        merged,
                        client.get("inbound_ids") or None,
                    )
                except Exception as exc:
                    warning = f"Клиент привязан, но не удалось записать tgId в панель: {exc}"

            try:
                account = _upsert_panel_client_account(db, user_id=user.id, panel=panel, client=client)
            except ValueError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400

            record_user_event(
                db,
                actor_user_id=auth["user_id"],
                subject_user_id=user.id,
                action="panel_client_bound",
                changes={
                    "panel_id": panel.id,
                    "email": client.get("email"),
                    "sub_id": client.get("sub_id"),
                    "inbound_ids": client.get("inbound_ids"),
                },
            )
            db.commit()
            payload = {"ok": True, "account": _serialize_panel_client_account(db, account)}
            if warning:
                payload["warning"] = warning
            return jsonify(payload)

    @app.get("/api/admin/panels")
    def admin_panels_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            rows = db.query(Panel).order_by(Panel.created_at.asc()).all()
            return jsonify({"ok": True, "panels": [_serialize_panel(row) for row in rows]})

    @app.get("/api/admin/panels/<panel_id>/metrics")
    def admin_panel_metrics(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            panel = db.query(Panel).filter(Panel.id == panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            row = db.query(AppSetting).filter(AppSetting.key == "telegram.panel_monitor_state").first()
            state = row.value_json if row and isinstance(row.value_json, dict) else {}
            metrics = state.get(panel.id) if isinstance(state.get(panel.id), dict) else {}
            return jsonify({
                "ok": True,
                "panel_id": panel.id,
                "health_status": panel.health_status,
                "updated_at": metrics.get("updated_at"),
                "text": metrics.get("text") or "Метрики появятся после следующего обновления мониторинга.",
            })

    @app.post("/api/admin/verification-codes")
    def admin_verification_codes_create():
        auth, err = _auth_context(require_role="support")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        count_raw = body.get("count") or 1
        length_raw = body.get("length") or 5
        try:
            count = max(1, min(50, int(count_raw)))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "count must be an integer"}), 400
        try:
            length = max(5, min(12, int(length_raw)))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "length must be an integer"}), 400

        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        created = []
        with SessionLocal() as db:
            for _ in range(count):
                code = "".join(secrets.choice(alphabet) for _ in range(length))
                row = VerificationCode(code=code, status="active", issued_by=auth["user_id"])
                db.add(row)
                created.append(code)
            db.commit()

        return jsonify({"ok": True, "codes": created})

    @app.post("/api/admin/verify-user")
    def admin_verify_user():
        auth, err = _auth_context(require_role="support")
        if err:
            return err

        body = request.get_json(silent=True) or {}
        user_id = body.get("user_id")
        telegram_id = body.get("telegram_id")
        if not user_id and not telegram_id:
            return jsonify({"ok": False, "error": "user_id or telegram_id is required"}), 400

        with SessionLocal() as db:
            user = None
            if user_id:
                user = db.query(User).filter(User.id == int(user_id)).first()
            if not user and telegram_id:
                user = db.query(User).filter(User.telegram_id == str(telegram_id)).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404

            user.status = "verified"
            db.add(
                UserVerification(
                    user_id=user.id,
                    method="manual",
                    code_id=None,
                    approved_by=auth["user_id"],
                )
            )
            db.commit()
            return jsonify({"ok": True, "user_id": user.id, "status": user.status})

    @app.post("/api/admin/panels/test-connection")
    def admin_panels_test_connection():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        provider = _normalize_panel_provider(body.get("provider"))
        base_url = str(body.get("base_url") or "").strip()
        auth_type = str(body.get("auth_type") or "login_password").strip().lower() or "login_password"
        if not base_url:
            return jsonify({"ok": False, "error": "base_url is required"}), 400
        region = str(body.get("region") or "").strip()
        if len(region) != 2 or not region.isascii() or not region.isalpha():
            return jsonify({"ok": False, "error": "region must be a two-letter location code"}), 400
        auth_payload = {
            "username": str(body.get("username") or body.get("login") or "").strip(),
            "password": str(body.get("password") or "").strip(),
            "token": str(body.get("token") or body.get("api_token") or "").strip(),
            "token_header": str(body.get("token_header") or "Authorization").strip(),
            "token_prefix": str(body.get("token_prefix") or "Bearer").strip(),
        }
        panel_stub = Panel(
            id=str(uuid4()),
            name=str(body.get("name") or "Panel").strip() or "Panel",
            provider=provider,
            base_url=base_url,
            auth_type=auth_type,
            auth_secret_ref=str(uuid4()),
            is_active=1,
            is_default=0,
        )
        try:
            result = panel_registry.get_provider(provider).health_check(panel_stub, auth_payload)
            return jsonify({"ok": True, "result": result})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 502

    @app.post("/api/admin/panels")
    def admin_panels_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        name = str(body.get("name") or "").strip()
        base_url = str(body.get("base_url") or "").strip()
        provider = _normalize_panel_provider(body.get("provider"))
        auth_type = str(body.get("auth_type") or "login_password").strip().lower() or "login_password"
        if not name:
            return jsonify({"ok": False, "error": "name is required"}), 400
        if not base_url:
            return jsonify({"ok": False, "error": "base_url is required"}), 400
        region = str(body.get("region") or "").strip()
        if len(region) != 2 or not region.isascii() or not region.isalpha():
            return jsonify({"ok": False, "error": "region must be a two-letter location code"}), 400
        if auth_type not in {"login_password", "api_token"}:
            return jsonify({"ok": False, "error": "unsupported auth_type"}), 400

        secret_payload = {
            "username": str(body.get("username") or body.get("login") or "").strip(),
            "password": str(body.get("password") or "").strip(),
            "token": str(body.get("token") or body.get("api_token") or "").strip(),
            "token_header": str(body.get("token_header") or "Authorization").strip(),
            "token_prefix": str(body.get("token_prefix") or "Bearer").strip(),
        }
        panel_stub = Panel(
            id=str(uuid4()),
            name=name[:120],
            provider=provider,
            base_url=base_url,
            auth_type=auth_type,
            auth_secret_ref=str(uuid4()),
            is_active=1,
            is_default=0,
        )
        try:
            panel_registry.get_provider(provider).health_check(panel_stub, secret_payload)
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 502
        with SessionLocal() as db:
            secret = PanelSecret(
                id=str(uuid4()),
                provider=provider,
                auth_type=auth_type,
                ciphertext=encrypt_payload(secret_payload),
            )
            db.add(secret)
            db.flush()

            row = Panel(
                id=str(uuid4()),
                name=name[:120],
                provider=provider,
                base_url=base_url[:512],
                auth_type=auth_type,
                auth_secret_ref=secret.id,
                is_active=1 if body.get("is_active", True) else 0,
                is_default=0,
                region=region.lower(),
                health_status="green",
                last_ok_at=utcnow(),
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(row)})

    @app.post("/api/admin/panels/<panel_id>")
    def admin_panels_update(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            row = db.query(Panel).filter(Panel.id == panel_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            if "name" in body:
                row.name = str(body.get("name") or "").strip()[:120] or row.name
            if "base_url" in body:
                base_url = str(body.get("base_url") or "").strip()
                if base_url:
                    row.base_url = base_url[:512]
            if "provider" in body:
                row.provider = _normalize_panel_provider(body.get("provider"))
            if "region" in body:
                row.region = str(body.get("region") or "").strip()[:16] or None
            if "auth_type" in body:
                row.auth_type = str(body.get("auth_type") or "").strip().lower() or row.auth_type
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(row)})

    @app.post("/api/admin/panels/<panel_id>/rotate-secret")
    def admin_panels_rotate_secret(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            panel = db.query(Panel).filter(Panel.id == panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            secret = db.query(PanelSecret).filter(PanelSecret.id == panel.auth_secret_ref).first()
            if not secret:
                return jsonify({"ok": False, "error": "Panel secret not found"}), 404

            payload = {
                "username": str(body.get("username") or body.get("login") or "").strip(),
                "password": str(body.get("password") or "").strip(),
                "token": str(body.get("token") or body.get("api_token") or "").strip(),
                "token_header": str(body.get("token_header") or "Authorization").strip(),
                "token_prefix": str(body.get("token_prefix") or "Bearer").strip(),
            }
            secret.auth_type = str(body.get("auth_type") or panel.auth_type).strip().lower() or panel.auth_type
            secret.ciphertext = encrypt_payload(payload)
            panel.auth_type = secret.auth_type
            panel_registry.invalidate_panel(panel.id)
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(panel)})

    @app.post("/api/admin/panels/<panel_id>/activate")
    def admin_panels_activate(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        is_active = 1 if body.get("is_active", True) else 0
        with SessionLocal() as db:
            panel = db.query(Panel).filter(Panel.id == panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            panel.is_active = is_active
            db.commit()
            return jsonify({"ok": True, "panel": _serialize_panel(panel)})

    @app.post("/api/admin/panels/<panel_id>/delete")
    def admin_panels_delete(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            result = _delete_panel(db, panel_id)
            if not result:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            db.commit()
            return jsonify({"ok": True, **result})
    @app.post("/api/admin/panels/<panel_id>/sync-inbounds")
    def admin_panel_sync_inbounds(panel_id: str):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            panel = db.query(Panel).filter(Panel.id == panel_id, Panel.is_active == 1).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found or inactive"}), 404
            try:
                provider = panel_registry.get_provider(panel.provider)
                auth_payload = panel_registry.get_auth_payload(db, panel)
                items = provider.list_inbounds(panel, auth_payload)
                seen: set[str] = set()
                for item in items:
                    row = _sync_single_inbound_from_panel(db, item, panel=panel)
                    seen.add(row.external_inbound_id)
                stale_rows = db.query(PanelInbound).filter(PanelInbound.panel_id == panel.id).all()
                stale_disabled = 0
                for stale in stale_rows:
                    if stale.external_inbound_id in seen:
                        continue
                    stale.enabled = 0
                    stale.last_sync_at = utcnow()
                    stale_disabled += 1
                panel.health_status = "green"
                panel.last_ok_at = utcnow()
                panel.error_message = None
                sync_group_members_from_inbounds(db)
                db.commit()
                return jsonify({"ok": True, "upserted": len(seen), "stale_disabled": stale_disabled})
            except Exception as exc:
                panel_registry.invalidate_panel(panel.id)
                panel.health_status = "red"
                panel.error_message = str(exc)[:500]
                db.commit()
                return jsonify({"ok": False, "error": str(exc)}), 502

    @app.get("/api/admin/panel-inbounds")
    def admin_panel_inbounds_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            rows = (
                db.query(PanelInbound, Panel)
                .join(Panel, Panel.id == PanelInbound.panel_id)
                .order_by(Panel.name.asc(), PanelInbound.id.asc())
                .all()
            )
            payload = []
            for inbound, panel in rows:
                payload.append(
                    {
                        "id": inbound.id,
                        "panel_id": panel.id,
                        "panel_name": panel.name,
                        "provider": panel.provider,
                        "region": panel.region,
                        "external_inbound_id": inbound.external_inbound_id,
                        "protocol": inbound.protocol,
                        "port": inbound.port,
                        "remark": inbound.remark,
                        "listen": inbound.listen,
                        "enabled": bool(inbound.enabled),
                        "show_in_app": bool(inbound.show_in_app),
                        "last_sync_at": inbound.last_sync_at.isoformat() if inbound.last_sync_at else None,
                        "updated_at": inbound.updated_at.isoformat() if inbound.updated_at else None,
                    }
                )
            return jsonify({"ok": True, "inbounds": payload})

    @app.post("/api/admin/panel-inbounds/<int:panel_inbound_ref_id>/visibility")
    def admin_panel_inbound_visibility(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        if "show_in_app" not in body:
            return jsonify({"ok": False, "error": "show_in_app is required"}), 400
        with SessionLocal() as db:
            inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            inbound.show_in_app = 1 if body.get("show_in_app") else 0
            db.commit()
            return jsonify(
                {
                    "ok": True,
                    "inbound": {
                        "id": inbound.id,
                        "show_in_app": bool(inbound.show_in_app),
                    },
                }
            )

    @app.get("/api/admin/panel-inbounds/<int:panel_inbound_ref_id>/clients")
    def admin_panel_inbound_clients(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            clients = extract_clients_from_panel_inbound(inbound)
            return jsonify(
                {
                    "ok": True,
                    "panel_inbound_ref_id": inbound.id,
                    "external_inbound_id": inbound.external_inbound_id,
                    "protocol": inbound.protocol,
                    "clients": clients,
                }
            )

    @app.post("/api/admin/panel-inbounds/<int:panel_inbound_ref_id>/clients")
    def admin_panel_inbound_clients_create(panel_inbound_ref_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        label = str(body.get("label") or body.get("email") or "").strip()
        if not label:
            return jsonify({"ok": False, "error": "label is required"}), 400
        with SessionLocal() as db:
            inbound = db.query(PanelInbound).filter(PanelInbound.id == panel_inbound_ref_id).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            panel = db.query(Panel).filter(Panel.id == inbound.panel_id).first()
            if not panel:
                return jsonify({"ok": False, "error": "Panel not found"}), 404
            protocol = str(inbound.protocol or "").strip().lower()
            if protocol != "vless":
                return jsonify({"ok": False, "error": "Only VLESS panel inbounds support add client"}), 400
            existing = extract_clients_from_panel_inbound(inbound)
            existing_labels = {str(item.get("label") or "").strip().lower() for item in existing}
            if label.lower() in existing_labels:
                return jsonify({"ok": False, "error": "Client with this label already exists"}), 409
            client_id = str(uuid4())
            client_payload = {
                "id": client_id,
                "email": label[:64],
                "flow": str(body.get("flow") or "xtls-rprx-vision").strip() or "xtls-rprx-vision",
                "limitIp": int(body.get("limit_ip") or 0),
                "totalGB": int(body.get("total_gb") or 0) * 1024 * 1024 * 1024,
                "expiryTime": 0,
                "enable": True,
                "tgId": 0,
                "subId": str(body.get("sub_id") or _generate_panel_sub_id()).strip()[:32] or _generate_panel_sub_id(),
                "reset": 0,
            }
            try:
                provider = panel_registry.get_provider(panel.provider)
                auth_payload = panel_registry.get_auth_payload(db, panel)
                panel_result = provider.create_client(panel, inbound, client_payload, auth_payload)
                items = provider.list_inbounds(panel, auth_payload)
                panel_item = next((item for item in items if str(item.get("id")) == str(inbound.external_inbound_id)), None)
                if panel_item:
                    inbound = _sync_single_inbound_from_panel(db, panel_item, panel=panel)
                clients = extract_clients_from_panel_inbound(inbound)
                db.commit()
                return jsonify(
                    {
                        "ok": True,
                        "panel_inbound_ref_id": inbound.id,
                        "created_client": next((item for item in clients if item.get("identifier") == client_id), None),
                        "clients": clients,
                        "panel_result": panel_result,
                    }
                )
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 502

    @app.get("/api/admin/inbound-groups")
    def admin_inbound_groups_list():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            groups = db.query(InboundGroup).order_by(InboundGroup.sort.asc(), InboundGroup.id.asc()).all()
            payload = []
            for group in groups:
                members = (
                    db.query(InboundGroupMember, PanelInbound, Panel)
                    .join(PanelInbound, PanelInbound.id == InboundGroupMember.panel_inbound_id)
                    .join(Panel, Panel.id == PanelInbound.panel_id)
                    .filter(InboundGroupMember.group_id == group.id)
                    .order_by(InboundGroupMember.priority.asc(), InboundGroupMember.id.asc())
                    .all()
                )
                payload.append(
                    {
                        "id": group.id,
                        "key": group.key,
                        "title": group.title,
                        "visible": bool(group.visible),
                        "sort": group.sort,
                        "members": [
                            {
                                "id": member.id,
                                "panel_inbound_id": member.panel_inbound_id,
                                "external_inbound_id": inbound.external_inbound_id,
                                "panel_id": panel.id,
                                "panel_name": panel.name,
                                "label": member.label,
                                "priority": member.priority,
                                "is_active": bool(member.is_active),
                            }
                            for member, inbound, panel in members
                        ],
                    }
                )
            return jsonify({"ok": True, "groups": payload})

    @app.post("/api/admin/inbound-groups")
    def admin_inbound_groups_create():
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        key = str(body.get("key") or "").strip().lower()
        title = str(body.get("title") or "").strip()
        if not key or not title:
            return jsonify({"ok": False, "error": "key and title are required"}), 400
        with SessionLocal() as db:
            existing = db.query(InboundGroup).filter(InboundGroup.key == key).first()
            if existing:
                return jsonify({"ok": False, "error": "Group key already exists"}), 409
            row = InboundGroup(
                key=key[:32],
                title=title[:64],
                visible=1 if body.get("visible", True) else 0,
                sort=int(body.get("sort") or 100),
            )
            db.add(row)
            db.commit()
            return jsonify({"ok": True, "group": {"id": row.id, "key": row.key, "title": row.title}})

    @app.post("/api/admin/inbound-groups/<int:group_id>")
    def admin_inbound_groups_update(group_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            row = db.query(InboundGroup).filter(InboundGroup.id == group_id).first()
            if not row:
                return jsonify({"ok": False, "error": "Group not found"}), 404
            if "title" in body:
                title = str(body.get("title") or "").strip()
                if title:
                    row.title = title[:64]
            if "visible" in body:
                row.visible = 1 if body.get("visible") else 0
            if "sort" in body:
                row.sort = int(body.get("sort") or row.sort)
            db.commit()
            return jsonify({"ok": True})

    @app.post("/api/admin/inbound-groups/<int:group_id>/members/upsert")
    def admin_inbound_group_members_upsert(group_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        panel_inbound_id = body.get("panel_inbound_id")
        if not panel_inbound_id:
            return jsonify({"ok": False, "error": "panel_inbound_id is required"}), 400
        with SessionLocal() as db:
            group = db.query(InboundGroup).filter(InboundGroup.id == group_id).first()
            if not group:
                return jsonify({"ok": False, "error": "Group not found"}), 404
            inbound = db.query(PanelInbound).filter(PanelInbound.id == int(panel_inbound_id)).first()
            if not inbound:
                return jsonify({"ok": False, "error": "Panel inbound not found"}), 404
            row = (
                db.query(InboundGroupMember)
                .filter(
                    InboundGroupMember.group_id == group.id,
                    InboundGroupMember.panel_inbound_id == inbound.id,
                )
                .first()
            )
            if not row:
                row = InboundGroupMember(group_id=group.id, panel_inbound_id=inbound.id)
                db.add(row)
            row.label = str(body.get("label") or inbound.remark or "").strip()[:120] or None
            row.priority = int(body.get("priority") or 100)
            row.is_active = 1 if body.get("is_active", True) else 0
            db.commit()
            return jsonify({"ok": True, "member_id": row.id})

    @app.post("/api/admin/inbound-groups/<int:group_id>/members/<int:member_id>/delete")
    def admin_inbound_group_members_delete(group_id: int, member_id: int):
        _, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            row = (
                db.query(InboundGroupMember)
                .filter(InboundGroupMember.id == member_id, InboundGroupMember.group_id == group_id)
                .first()
            )
            if not row:
                return jsonify({"ok": False, "error": "Group member not found"}), 404
            db.delete(row)
            db.commit()
            return jsonify({"ok": True, "deleted": True})

    @app.post("/api/admin/broadcasts")
    def admin_broadcast():
        """Рассылка от имени бота выбранным клиентам (Markdown в тексте)."""
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        type_key = str(body.get("type") or "").strip()
        text = str(body.get("text") or "").strip()
        raw_ids = body.get("user_ids")
        if type_key not in broadcasts.BROADCAST_TYPES:
            return jsonify({"ok": False, "error": "Выберите тип сообщения"}), 400
        if not text:
            return jsonify({"ok": False, "error": "Введите текст рассылки"}), 400
        if len(text) > broadcasts.MAX_TEXT_LENGTH:
            return jsonify({"ok": False, "error": f"Текст слишком длинный (максимум {broadcasts.MAX_TEXT_LENGTH} символов)"}), 400
        try:
            user_ids = list(dict.fromkeys(int(value) for value in (raw_ids or [])))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Некорректный список получателей"}), 400
        if not user_ids:
            return jsonify({"ok": False, "error": "Выберите получателей"}), 400
        if len(user_ids) > broadcasts.MAX_RECIPIENTS:
            return jsonify({"ok": False, "error": f"Слишком много получателей (максимум {broadcasts.MAX_RECIPIENTS})"}), 400
        with SessionLocal() as db:
            found = {row.id: row for row in db.query(User).filter(User.id.in_(user_ids)).all()}
            recipients = [found[uid] for uid in user_ids if uid in found]
            if not recipients:
                return jsonify({"ok": False, "error": "Получатели не найдены"}), 404
            actor = db.query(User).filter(User.id == auth["user_id"]).first()
            result = broadcasts.send_broadcast(recipients, type_key, text)
            log_text = broadcasts.format_log(actor, type_key, text, recipients, result.failed)
            log_posted = post_operator_topic(USER_EVENTS_TOPIC, log_text, parse_mode="HTML")
            record_user_event(
                db,
                actor_user_id=auth["user_id"],
                subject_user_id=None,
                action="broadcast_sent",
                changes={
                    "type": type_key,
                    "total": len(recipients),
                    "sent": len(result.sent),
                    "failed": len(result.failed),
                },
            )
            db.commit()
            return jsonify(
                {
                    "ok": True,
                    "total": len(recipients),
                    "sent": len(result.sent),
                    "failed": [
                        {
                            "user_id": user.id,
                            "name": user.name,
                            "username": user.username,
                            "reason": reason,
                        }
                        for user, reason in result.failed
                    ],
                    "log_posted": bool(log_posted),
                }
            )

    @app.post("/api/admin/users/<int:user_id>/identity")
    def admin_user_identity(user_id: int):
        """Ручная правка имени, username и Telegram ID клиента."""
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        try:
            values = user_deletion.normalize_identity(body)
        except user_deletion.IdentityError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            new_telegram_id = values.get("telegram_id")
            if "telegram_id" in values and new_telegram_id:
                clash = db.query(User).filter(User.telegram_id == new_telegram_id, User.id != user.id).first()
                identity_clash = db.query(AuthIdentity).filter(
                    AuthIdentity.provider == "telegram",
                    AuthIdentity.provider_user_id == new_telegram_id,
                    AuthIdentity.user_id != user.id,
                ).first()
                if clash or identity_clash:
                    return jsonify({"ok": False, "error": "Этот Telegram ID уже занят другим пользователем"}), 409
            changes = {
                key: {"old": getattr(user, key), "new": value}
                for key, value in values.items()
                if getattr(user, key) != value
            }
            for key, value in values.items():
                setattr(user, key, value)
            if "telegram_id" in changes and new_telegram_id:
                db.query(AuthIdentity).filter(
                    AuthIdentity.user_id == user.id, AuthIdentity.provider == "telegram"
                ).update({AuthIdentity.provider_user_id: new_telegram_id})
            if changes:
                record_user_event(
                    db,
                    actor_user_id=auth["user_id"],
                    subject_user_id=user.id,
                    action="user_identity_changed",
                    changes=changes,
                )
            db.commit()
            db.refresh(user)
            return jsonify({"ok": True, "overview": _serialize_admin_user_overview(db, user)})

    @app.delete("/api/admin/users/<int:user_id>")
    def admin_user_delete(user_id: int):
        """Полностью удаляет клиента (чистка мусорных записей). Себя удалить нельзя."""
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        if auth["user_id"] == user_id:
            return jsonify({"ok": False, "error": "Нельзя удалить самого себя"}), 400
        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            deleted = {"id": user.id, "name": user.name, "username": user.username, "telegram_id": user.telegram_id}
            summary = user_deletion.delete_user(db, user)
            record_user_event(
                db,
                actor_user_id=auth["user_id"],
                subject_user_id=None,
                action="user_deleted",
                changes={"deleted": deleted, **summary},
            )
            db.commit()
        return jsonify({"ok": True, **summary})

    @app.post("/api/admin/users/<int:user_id>/freeze")
    def admin_user_freeze(user_id: int):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        frozen = bool(body.get("frozen", True))
        failures = []
        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            subscriptions = db.query(Subscription).filter(Subscription.user_id == user.id).all()
            was_frozen = any(item.is_frozen for item in subscriptions)
            for subscription in subscriptions:
                subscription.is_frozen = frozen
            accounts = db.query(VpnAccount).filter(VpnAccount.user_id == user.id).all()
            for account in accounts:
                if frozen and account.status != "active":
                    continue
                if not frozen and account.status != "frozen":
                    continue
                inbound = db.query(PanelInbound).filter(PanelInbound.id == account.panel_inbound_ref_id).first()
                if not inbound or not account.identifier:
                    continue
                panel = db.query(Panel).filter(Panel.id == inbound.panel_id).first()
                if not panel:
                    continue
                try:
                    provider = panel_registry.get_provider(panel.provider)
                    result = provider.update_client(
                        panel,
                        account.identifier,
                        {"inbound_id": inbound.external_inbound_id, "enabled": not frozen},
                        panel_registry.get_auth_payload(db, panel),
                    )
                    if isinstance(result, dict) and not result.get("ok", True):
                        failures.append({"account_id": account.id, "error": "panel rejected status change"})
                        continue
                    account.status = "frozen" if frozen else "active"
                except Exception as exc:
                    failures.append({"account_id": account.id, "error": str(exc)})
            record_user_event(
                db,
                actor_user_id=auth["user_id"],
                subject_user_id=user.id,
                action="user_frozen" if frozen else "user_unfrozen",
                changes={"frozen": frozen, "failed_connections": len(failures)},
            )
            db.commit()
            if subscriptions and was_frozen != frozen:
                subscription_updates.notify_subscription_updated(
                    db,
                    user,
                    {"status": "", "access_until": None, "price": None, "frozen": was_frozen},
                    {"status": "", "access_until": None, "price": None, "frozen": frozen},
                )
        return jsonify({"ok": not failures, "frozen": frozen, "failures": failures})

    @app.post("/api/admin/users/<int:user_id>/manual-extend")
    def admin_user_manual_extend(user_id: int):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        if body.get("confirmed") is not True:
            return jsonify({"ok": False, "confirmation_required": True, "error": "Repeat with confirmed=true to extend"}), 409
        with SessionLocal() as db:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return jsonify({"ok": False, "error": "User not found"}), 404
            result = _apply_admin_subscription_payload(db, user, {"extend_months": body.get("months", 1)})
            if result:
                db.rollback()
                return result
            subscription = _admin_latest_subscription(db, user.id)
            if not subscription:
                db.rollback()
                return jsonify({"ok": False, "error": "Subscription not found"}), 404
            next_payment = subscription.access_until
            telegram_id = user.telegram_id
            silent_notice = is_silent(user, "payment_confirmed")
            record_user_event(
                db,
                actor_user_id=auth["user_id"],
                subject_user_id=user.id,
                action="subscription_manually_extended",
                changes={"months": body.get("months", 1), "access_until": next_payment.isoformat() if next_payment else None},
            )
            db.commit()
            overview = _serialize_admin_user_overview(db, user)
        notification_sent = False
        if telegram_id:
            notification_sent = send_raw(
                telegram_id,
                "Администратор подтвердил продление подписки, спасибо большое 💜\n\n"
                + "Следующая оплата: "
                + (next_payment.strftime("%d.%m.%Y") if next_payment else "не указана"),
                silent=silent_notice,
            )
        return jsonify({"ok": True, "overview": overview, "notification_sent": notification_sent})

__all__ = ["register_admin_routes"]
