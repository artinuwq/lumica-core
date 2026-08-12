from __future__ import annotations


def register_group_routes(app, deps):
    # Transitional dependency injection, same pattern as the other route modules.
    globals().update(deps)

    from lumica.domain.models import Group, Subscription, User
    from lumica.services import groups as group_service

    def _serialize_member(user: User, *, is_admin: bool) -> dict:
        return {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "telegram_id": user.telegram_id,
            "is_admin": is_admin,
        }

    def _serialize_group(db, group: Group) -> dict:
        members = db.query(User).filter(User.group_id == group.id).all()
        return {
            "id": group.id,
            "name": group.name,
            "admin_user_id": group.admin_user_id,
            "created_at": group.created_at.isoformat() if group.created_at else None,
            "members": [_serialize_member(m, is_admin=(m.id == group.admin_user_id)) for m in members],
        }

    def _find_group(db, group_id: int):
        group = db.query(Group).filter(Group.id == group_id).first()
        if not group:
            return None, (jsonify({"ok": False, "error": "Группа не найдена"}), 404)
        return group, None

    @app.get("/api/groups/mine")
    def my_group_route():
        """Для обычного участника - краткая сводка по своей группе (без
        чужих технических данных). Для администратора группы - полный
        список участников со статусами подписок (ТЗ п.16)."""
        auth, err = _auth_context()
        if err:
            return err
        with SessionLocal() as db:
            user = db.query(User).filter(User.id == auth["user_id"]).first()
            if not user or not user.group_id:
                return jsonify({"ok": True, "data": None})

            group = db.query(Group).filter(Group.id == user.group_id).first()
            if not group:
                return jsonify({"ok": True, "data": None})

            is_admin = group_service.is_group_admin(user, group)
            if not is_admin:
                return jsonify(
                    {
                        "ok": True,
                        "data": {
                            "id": group.id,
                            "name": group.name,
                            "is_admin": False,
                            "member_count": db.query(User).filter(User.group_id == group.id).count(),
                        },
                    }
                )

            members = db.query(User).filter(User.group_id == group.id).all()
            member_data = []
            for member in members:
                subscription = (
                    db.query(Subscription)
                    .filter(Subscription.user_id == member.id)
                    .order_by(Subscription.created_at.desc())
                    .first()
                )
                member_data.append(
                    {
                        **_serialize_member(member, is_admin=(member.id == group.admin_user_id)),
                        "subscription_status": subscription.status if subscription else None,
                        "access_until": subscription.access_until.isoformat()
                        if subscription and subscription.access_until
                        else None,
                    }
                )
            return jsonify(
                {"ok": True, "data": {"id": group.id, "name": group.name, "is_admin": True, "members": member_data}}
            )

    @app.get("/api/groups")
    def list_groups_route():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            groups = db.query(Group).order_by(Group.created_at.desc()).all()
            return jsonify({"ok": True, "data": [_serialize_group(db, g) for g in groups]})

    @app.post("/api/groups")
    def create_group_route():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            try:
                group = group_service.create_group(
                    db, name=body.get("name"), admin_user_id=body.get("admin_user_id")
                )
                db.commit()
            except group_service.GroupError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize_group(db, group)}), 201

    @app.patch("/api/groups/<int:group_id>")
    def update_group_route(group_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            group, err = _find_group(db, group_id)
            if err:
                return err
            try:
                if "name" in body:
                    group_service.rename_group(db, group, name=body.get("name"))
                if body.get("admin_user_id") is not None:
                    group_service.set_admin(db, group, int(body["admin_user_id"]))
                db.commit()
            except group_service.GroupError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize_group(db, group)})

    @app.delete("/api/groups/<int:group_id>")
    def delete_group_route(group_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            group, err = _find_group(db, group_id)
            if err:
                return err
            group_service.delete_group(db, group)
            db.commit()
            return jsonify({"ok": True, "data": {"deleted": True}})

    @app.post("/api/groups/<int:group_id>/members")
    def add_group_member_route(group_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        user_id_raw = body.get("user_id")
        try:
            user_id = int(user_id_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "user_id must be an integer"}), 400
        with SessionLocal() as db:
            group, err = _find_group(db, group_id)
            if err:
                return err
            try:
                group_service.add_member(db, group, user_id)
                db.commit()
            except group_service.GroupError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize_group(db, group)})

    @app.delete("/api/groups/<int:group_id>/members/<int:user_id>")
    def remove_group_member_route(group_id, user_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            group, err = _find_group(db, group_id)
            if err:
                return err
            try:
                group_service.remove_member(db, group, user_id)
                db.commit()
            except group_service.GroupError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize_group(db, group)})


__all__ = ["register_group_routes"]
