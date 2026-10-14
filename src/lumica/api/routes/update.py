from __future__ import annotations


def register_update_routes(app, deps):
    # Transitional dependency injection, same pattern as the other route modules.
    globals().update(deps)

    from lumica.update import UpdateManager

    @app.get("/api/update/status")
    def update_status():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        manager = UpdateManager()
        data = manager.check().to_dict()
        data["last_result"] = manager.last_result()
        return jsonify({"ok": True, "data": data})

    @app.post("/api/update")
    def update_apply():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        force = bool((request.get_json(silent=True) or {}).get("force"))
        # The restart would kill this very process mid-request, so the update
        # runs in the separate lumica-update.service unit (see UpdateManager).
        result = UpdateManager().apply_background(force=force)
        status_code = 202 if result.started else (200 if result.success else 500)
        return jsonify({"ok": result.success, "data": result.to_dict()}), status_code

    @app.post("/api/restart")
    def restart_service():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        restarted, message = UpdateManager().restart_service()
        status_code = 200 if restarted else 500
        return jsonify({"ok": restarted, "data": {"restarted": restarted, "message": message}}), status_code


__all__ = ["register_update_routes"]
