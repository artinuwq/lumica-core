from __future__ import annotations

def register_status_routes(app, deps):
    # Transitional dependency injection while handlers are being migrated out
    # of shared app helper closures.
    globals().update(deps)

    @app.get("/api/status")
    def status_public():
        panel_host, panel_port = _panel_host_port()
        with SessionLocal() as db:
            vless_inbound = _inbound_for_protocol(db, "vless")
            http_inbound = _inbound_for_protocol(db, "http")
            mixed_inbound = _inbound_for_protocol(db, "mixed")
            vless_visible = _protocol_visible_in_app(db, "vless")
            http_visible = _protocol_visible_in_app(db, "http")
            mixed_visible = _protocol_visible_in_app(db, "mixed")
            panels_payload, panel_summary = _panels_status_payload(db, refresh=False)

        vless_status = _service_status(vless_inbound)
        http_status = _service_status(http_inbound)
        mixed_status = _service_status(mixed_inbound)
        vless_status["visible_in_app"] = vless_visible
        http_status["visible_in_app"] = http_visible
        mixed_status["visible_in_app"] = mixed_visible
        https_mixed_status = {
            "ok": bool(http_status.get("ok")) or bool(mixed_status.get("ok")),
            "configured": bool(http_status.get("configured")) or bool(mixed_status.get("configured")),
            "port": http_status.get("port") or mixed_status.get("port"),
            "panel_inbound_id": http_status.get("panel_inbound_id") or mixed_status.get("panel_inbound_id"),
            "visible_in_app": http_visible or mixed_visible,
            "error": None,
        }

        return jsonify(
            {
                "ok": True,
                "panel": {"ok": check_port(panel_host, panel_port), "host": panel_host, "port": panel_port},
                "services": {
                    "vless": vless_status,
                    "http": http_status,
                    "mixed": mixed_status,
                    "https_mixed": https_mixed_status,
                },
                "panels": panels_payload,
                "panels_summary": panel_summary,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

    @app.get("/api/admin/status")
    def status_admin():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err

        panel_host, panel_port = _panel_host_port()
        with SessionLocal() as db:
            vless_inbound = _inbound_for_protocol(db, "vless")
            http_inbound = _inbound_for_protocol(db, "http")
            mixed_inbound = _inbound_for_protocol(db, "mixed")
            vless_visible = _protocol_visible_in_app(db, "vless")
            http_visible = _protocol_visible_in_app(db, "http")
            mixed_visible = _protocol_visible_in_app(db, "mixed")
            panels_payload, panel_summary = _panels_status_payload(db, refresh=True)
            db.commit()

        vless_status = _service_status(vless_inbound)
        http_status = _service_status(http_inbound)
        mixed_status = _service_status(mixed_inbound)
        vless_status["visible_in_app"] = vless_visible
        http_status["visible_in_app"] = http_visible
        mixed_status["visible_in_app"] = mixed_visible
        https_mixed_status = {
            "ok": bool(http_status.get("ok")) or bool(mixed_status.get("ok")),
            "configured": bool(http_status.get("configured")) or bool(mixed_status.get("configured")),
            "port": http_status.get("port") or mixed_status.get("port"),
            "panel_inbound_id": http_status.get("panel_inbound_id") or mixed_status.get("panel_inbound_id"),
            "visible_in_app": http_visible or mixed_visible,
            "error": None,
        }

        return jsonify(
            {
                "ok": True,
                "admin": auth,
                "panel": {"ok": check_port(panel_host, panel_port), "host": panel_host, "port": panel_port},
                "services": {
                    "vless": vless_status,
                    "http": http_status,
                    "mixed": mixed_status,
                    "https_mixed": https_mixed_status,
                },
                "panels": panels_payload,
                "panels_summary": panel_summary,
                "system": system_stats(),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

__all__ = ["register_status_routes"]
