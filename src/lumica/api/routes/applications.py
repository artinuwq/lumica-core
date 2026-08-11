from __future__ import annotations


def register_application_routes(app, deps):
    # Transitional dependency injection, same pattern as the other route modules.
    globals().update(deps)

    from lumica.domain.models import Application
    from lumica.services import applications as application_service

    def _serialize(application: Application) -> dict:
        return {
            "id": application.id,
            "user_id": application.user_id,
            "full_name": application.full_name,
            "tariff_id": application.tariff_id,
            "needs_proxy": bool(application.needs_proxy),
            "extra_info": application.extra_info,
            "status": application.status,
            "reviewed_by": application.reviewed_by,
            "reviewed_at": application.reviewed_at.isoformat() if application.reviewed_at else None,
            "review_note": application.review_note,
            "created_at": application.created_at.isoformat() if application.created_at else None,
        }

    def _find(db, application_id: int):
        application = db.query(Application).filter(Application.id == application_id).first()
        if not application:
            return None, (jsonify({"ok": False, "error": "Заявка не найдена"}), 404)
        return application, None

    @app.post("/api/applications")
    def create_application_route():
        auth, err = _auth_context()
        if err:
            return err

        body = request.get_json(silent=True) or {}
        tariff_id = body.get("tariff_id")
        try:
            tariff_id = int(tariff_id) if tariff_id not in (None, "") else None
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "tariff_id must be an integer"}), 400

        with SessionLocal() as db:
            try:
                application = application_service.create_application(
                    db,
                    user_id=auth["user_id"],
                    full_name=body.get("full_name"),
                    tariff_id=tariff_id,
                    needs_proxy=bool(body.get("needs_proxy")),
                    extra_info=body.get("extra_info"),
                )
                db.commit()
            except application_service.ApplicationError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(application)}), 201

    @app.get("/api/applications/mine")
    def my_applications_route():
        auth, err = _auth_context()
        if err:
            return err
        with SessionLocal() as db:
            items = (
                db.query(Application)
                .filter(Application.user_id == auth["user_id"])
                .order_by(Application.created_at.desc())
                .all()
            )
            return jsonify({"ok": True, "data": [_serialize(a) for a in items]})

    @app.get("/api/applications")
    def list_applications_route():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        status_filter = (request.args.get("status") or "").strip() or None
        with SessionLocal() as db:
            query = db.query(Application).order_by(Application.created_at.desc())
            if status_filter:
                query = query.filter(Application.status == status_filter)
            items = [_serialize(a) for a in query.limit(200).all()]
        return jsonify({"ok": True, "data": items})

    @app.post("/api/applications/<int:application_id>/review")
    def review_application_route(application_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            application, err = _find(db, application_id)
            if err:
                return err
            try:
                application_service.start_review(db, application, staff_user_id=auth["user_id"])
                db.commit()
            except application_service.ApplicationError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(application)})

    @app.post("/api/applications/<int:application_id>/need-info")
    def need_info_application_route(application_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            application, err = _find(db, application_id)
            if err:
                return err
            try:
                application_service.request_more_info(
                    db, application, staff_user_id=auth["user_id"], note=body.get("note")
                )
                db.commit()
            except application_service.ApplicationError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(application)})

    @app.post("/api/applications/<int:application_id>/approve")
    def approve_application_route(application_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            application, err = _find(db, application_id)
            if err:
                return err
            try:
                user = application_service.approve(db, application, staff_user_id=auth["user_id"])
                db.commit()
            except application_service.ApplicationError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": {"application": _serialize(application), "user_id": user.id}})

    @app.post("/api/applications/<int:application_id>/reject")
    def reject_application_route(application_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            application, err = _find(db, application_id)
            if err:
                return err
            try:
                application_service.reject(db, application, staff_user_id=auth["user_id"], note=body.get("note"))
                db.commit()
            except application_service.ApplicationError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(application)})

    @app.post("/api/applications/<int:application_id>/cancel")
    def cancel_application_route(application_id):
        auth, err = _auth_context()
        if err:
            return err
        with SessionLocal() as db:
            application, err = _find(db, application_id)
            if err:
                return err
            is_owner = application.user_id == auth["user_id"]
            if not is_owner and not _role_allows(auth.get("role"), "admin"):
                return jsonify({"ok": False, "error": "Forbidden"}), 403
            try:
                application_service.cancel(db, application)
                db.commit()
            except application_service.ApplicationError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(application)})


__all__ = ["register_application_routes"]
