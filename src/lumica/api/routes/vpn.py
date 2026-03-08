from __future__ import annotations

def register_vpn_routes(app, deps):
    # Transitional dependency injection while handlers are being migrated out
    # of shared app helper closures.
    globals().update(deps)

    @app.get("/api/vpn/config")
    def vpn_config():
        auth, err = _auth_context()
        if err:
            return err

        host = os.getenv("PUBLIC_VPN_HOST") or request.host.split(":")[0]
        subscription_cache: dict[str, list[str]] = {}

        with SessionLocal() as db:
            sub = _active_subscription(db, auth["user_id"])
            if not sub:
                return jsonify({"ok": False, "error": "Active subscription required"}), 403

            candidates, selected, strategy, selected_member_id = _resolve_selected_candidate(db, auth["user_id"], "vless")
            if not candidates:
                return jsonify({"ok": False, "error": "Visible VLESS account not found"}), 404

            connections: list[dict] = []
            servers: list[dict] = []
            for item in candidates:
                account = item["account"]
                inbound = item["inbound"]
                port = int(inbound.port)
                meta = account.meta_json or {}
                subscription_url = meta.get("sub_url")
                subscription_urls = _build_subscription_urls(meta.get("sub_id"), subscription_url)

                vless_url = meta.get("vless_url")
                if not vless_url and subscription_urls:
                    for candidate_url in subscription_urls:
                        cached_links = subscription_cache.get(candidate_url)
                        if cached_links is None:
                            cached_links = _load_subscription_links(candidate_url, quiet=True)
                            subscription_cache[candidate_url] = cached_links
                        if not cached_links:
                            continue
                        picked = _pick_vless_from_subscription(cached_links, account.identifier)
                        if not picked:
                            continue
                        vless_url = picked
                        subscription_url = candidate_url
                        break
                    if not vless_url and subscription_urls:
                        subscription_url = subscription_urls[0]
                if not vless_url and account.identifier:
                    query_params = {
                        "type": meta.get("type", "tcp"),
                        "security": meta.get("security", "reality"),
                        "flow": meta.get("flow", "xtls-rprx-vision"),
                        "sni": meta.get("sni", host),
                        "fp": meta.get("fp", "chrome"),
                    }
                    if meta.get("pbk"):
                        query_params["pbk"] = meta.get("pbk")
                    if meta.get("sid"):
                        query_params["sid"] = meta.get("sid")
                    q = urlencode({k: v for k, v in query_params.items() if v})
                    label = quote(account.label or "lumica")
                    vless_url = f"vless://{account.identifier}@{host}:{port}?{q}#{label}"
                if vless_url:
                    vless_url = _apply_vless_display_name(vless_url, account.label, account.identifier)

                panel_inbound_id = None
                try:
                    panel_inbound_id = int(getattr(inbound, "external_inbound_id", ""))
                except (TypeError, ValueError):
                    panel_inbound_id = None

                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"vless-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": account.panel_inbound_ref_id,
                        "inbound_remark": inbound.remark,
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "member_id": item.get("member_id"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                        "host": host,
                        "port": port,
                        "sub_id": meta.get("sub_id"),
                        "subscription_url": subscription_url,
                        "vless_url": vless_url,
                    }
                )
                servers.append(
                    {
                        "member_id": item.get("member_id"),
                        "label": account.label or account.identifier or f"vless-{account.id}",
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                    }
                )

            first = connections[0]
            db.commit()

            return jsonify(
                {
                    "ok": True,
                    "protocol": "vless",
                    "group_key": "vless",
                    "selected_member_id": selected_member_id,
                    "applied_strategy": strategy,
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "identifier": first.get("identifier"),
                    "sub_id": first.get("sub_id"),
                    "subscription_url": first.get("subscription_url"),
                    "vless_url": first.get("vless_url"),
                    "servers": servers,
                    "connections": connections,
                    "total": len(connections),
                }
            )

    @app.get("/api/vpn/mixed")
    def vpn_mixed():
        auth, err = _auth_context()
        if err:
            return err

        host = os.getenv("PUBLIC_VPN_HOST") or request.host.split(":")[0]

        with SessionLocal() as db:
            sub = _active_subscription(db, auth["user_id"])
            if not sub:
                return jsonify({"ok": False, "error": "Active subscription required"}), 403

            candidates, selected, strategy, selected_member_id = _resolve_selected_candidate(db, auth["user_id"], "mixed")
            if not candidates:
                return jsonify({"ok": False, "error": "Visible MIXED account not found"}), 404

            connections: list[dict] = []
            servers: list[dict] = []
            for item in candidates:
                account = item["account"]
                inbound = item["inbound"]
                port = int(inbound.port)
                username = account.identifier
                password = account.secret
                if not username or not password:
                    continue

                socks_url = f"socks5://{username}:{password}@{host}:{port}"
                http_url = f"http://{username}:{password}@{host}:{port}"
                panel_inbound_id = None
                try:
                    panel_inbound_id = int(getattr(inbound, "external_inbound_id", ""))
                except (TypeError, ValueError):
                    panel_inbound_id = None
                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"mixed-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": account.panel_inbound_ref_id,
                        "inbound_remark": inbound.remark,
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "member_id": item.get("member_id"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                        "urls": [socks_url, http_url],
                    }
                )
                servers.append(
                    {
                        "member_id": item.get("member_id"),
                        "label": account.label or account.identifier or f"mixed-{account.id}",
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                    }
                )

            if not connections:
                return jsonify({"ok": False, "error": "Visible MIXED accounts have no credentials"}), 409

            first = connections[0]
            db.commit()

            return jsonify(
                {
                    "ok": True,
                    "protocol": "mixed",
                    "group_key": "socks5",
                    "selected_member_id": selected_member_id,
                    "applied_strategy": strategy,
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "username": first.get("username"),
                    "password": first.get("password"),
                    "urls": first.get("urls"),
                    "servers": servers,
                    "connections": connections,
                    "total": len(connections),
                }
            )

    @app.get("/api/vpn/http")
    def vpn_http():
        auth, err = _auth_context()
        if err:
            return err

        host = os.getenv("PUBLIC_VPN_HOST") or request.host.split(":")[0]

        with SessionLocal() as db:
            sub = _active_subscription(db, auth["user_id"])
            if not sub:
                return jsonify({"ok": False, "error": "Active subscription required"}), 403

            candidates, selected, strategy, selected_member_id = _resolve_selected_candidate(db, auth["user_id"], "http")
            if not candidates:
                return jsonify({"ok": False, "error": "Visible HTTP account not found"}), 404

            connections: list[dict] = []
            servers: list[dict] = []
            for item in candidates:
                account = item["account"]
                inbound = item["inbound"]
                port = int(inbound.port)
                username = account.identifier
                password = account.secret
                if not username or not password:
                    continue

                http_url = f"http://{username}:{password}@{host}:{port}"
                panel_inbound_id = None
                try:
                    panel_inbound_id = int(getattr(inbound, "external_inbound_id", ""))
                except (TypeError, ValueError):
                    panel_inbound_id = None
                connections.append(
                    {
                        "account_id": account.id,
                        "label": account.label or account.identifier or f"http-{account.id}",
                        "identifier": account.identifier,
                        "panel_inbound_id": panel_inbound_id,
                        "panel_inbound_ref_id": account.panel_inbound_ref_id,
                        "inbound_remark": inbound.remark,
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "member_id": item.get("member_id"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                        "host": host,
                        "port": port,
                        "username": username,
                        "password": password,
                        "urls": [http_url],
                    }
                )
                servers.append(
                    {
                        "member_id": item.get("member_id"),
                        "label": account.label or account.identifier or f"http-{account.id}",
                        "panel_id": item.get("panel_id"),
                        "panel_name": item.get("panel_name"),
                        "region": item.get("region"),
                        "selected": bool(selected and selected.get("account").id == account.id),
                    }
                )

            if not connections:
                return jsonify({"ok": False, "error": "Visible HTTP accounts have no credentials"}), 409

            first = connections[0]
            db.commit()
            return jsonify(
                {
                    "ok": True,
                    "protocol": "http",
                    "group_key": "socks5",
                    "selected_member_id": selected_member_id,
                    "applied_strategy": strategy,
                    "host": first.get("host"),
                    "port": first.get("port"),
                    "username": first.get("username"),
                    "password": first.get("password"),
                    "urls": first.get("urls"),
                    "servers": servers,
                    "connections": connections,
                    "total": len(connections),
                }
            )

    @app.post("/api/vpn/select-server")
    def vpn_select_server():
        auth, err = _auth_context()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        group_key = str(body.get("group_key") or "").strip().lower()
        member_id_raw = body.get("member_id")
        strategy_raw = body.get("strategy")
        strategy = (
            _normalize_selection_strategy(strategy_raw)
            if strategy_raw not in (None, "")
            else "manual"
        )
        if group_key not in {"vless", "socks5"}:
            return jsonify({"ok": False, "error": "group_key must be vless or socks5"}), 400
        try:
            member_id = int(member_id_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "member_id must be an integer"}), 400

        with SessionLocal() as db:
            user_conn = _ensure_user_connection(db, auth["user_id"], group_key)
            if not user_conn:
                return jsonify({"ok": False, "error": "Group not found"}), 404
            member = (
                db.query(InboundGroupMember)
                .filter(
                    InboundGroupMember.id == member_id,
                    InboundGroupMember.group_id == user_conn.group_id,
                    InboundGroupMember.is_active == 1,
                )
                .first()
            )
            if not member:
                return jsonify({"ok": False, "error": "Group member not found or inactive"}), 404
            user_conn.selected_member_id = member.id
            user_conn.selection_strategy = strategy
            db.commit()
            return jsonify(
                {
                    "ok": True,
                    "selected_member_id": member.id,
                    "applied_strategy": user_conn.selection_strategy,
                }
            )

__all__ = ["register_vpn_routes"]
