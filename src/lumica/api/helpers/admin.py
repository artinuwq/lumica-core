from __future__ import annotations

def build_admin_helpers(deps):
    # Transitional dependency injection: helpers still depend on
    # legacy names while extraction to service classes continues.
    globals().update(deps)

    def check_port(host: str, port: int, timeout: float = 1.0):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _panel_host_port() -> tuple[str, int]:
        base = os.getenv("PANEL_BASE_URL", "http://127.0.0.1:2053/panel/api")
        parsed = urlparse(base)
        host = parsed.hostname or "127.0.0.1"
        if parsed.port:
            return host, parsed.port
        return host, 443 if parsed.scheme == "https" else 80

    def _panel_by_inbound_ref(db, inbound_ref_id: int | None) -> tuple[PanelInbound | None, Panel | None]:
        if not inbound_ref_id:
            return None, None
        inbound_row = db.query(PanelInbound).filter(PanelInbound.id == int(inbound_ref_id)).first()
        if not inbound_row:
            return None, None
        panel = db.query(Panel).filter(Panel.id == inbound_row.panel_id).first()
        return inbound_row, panel

    def _panel_inbound_snapshot(inbound_row: PanelInbound) -> SimpleNamespace:
        panel_inbound_id = None
        try:
            panel_inbound_id = int(inbound_row.external_inbound_id)
        except (TypeError, ValueError):
            panel_inbound_id = None
        return SimpleNamespace(
            id=inbound_row.id,
            panel_inbound_id=panel_inbound_id,
            external_inbound_id=inbound_row.external_inbound_id,
            protocol=inbound_row.protocol,
            port=inbound_row.port,
            remark=inbound_row.remark,
            listen=inbound_row.listen,
            enable=inbound_row.enabled,
            show_in_app=inbound_row.show_in_app,
            stream_settings=inbound_row.stream_settings if isinstance(inbound_row.stream_settings, dict) else {},
            settings=inbound_row.settings if isinstance(inbound_row.settings, dict) else {},
            panel_id=inbound_row.panel_id,
        )

    def _resolve_account_inbound(db, account: VpnAccount):
        if not account.panel_inbound_ref_id:
            return None, None, None
        inbound_row, panel = _panel_by_inbound_ref(db, account.panel_inbound_ref_id)
        if not inbound_row:
            return None, None, panel
        return _panel_inbound_snapshot(inbound_row), inbound_row, panel

    def _protocol_variants(protocol: str) -> set[str]:
        value = (protocol or "").strip().lower()
        if value == "https_mixed":
            return {"http", "mixed", "socks", "socks5"}
        if value == "mixed":
            return {"mixed", "socks", "socks5"}
        if value == "http":
            return {"http"}
        return {value}

    def _inbound_for_protocol(db, protocol: str):
        variants = _protocol_variants(protocol)
        panel_row = (
            db.query(PanelInbound)
            .join(Panel, Panel.id == PanelInbound.panel_id)
            .filter(
                PanelInbound.protocol.in_(variants),
                PanelInbound.enabled == 1,
                PanelInbound.port.isnot(None),
                Panel.is_active == 1,
            )
            .order_by(PanelInbound.updated_at.desc(), PanelInbound.id.desc())
            .first()
        )
        if panel_row:
            return _panel_inbound_snapshot(panel_row)
        return None

    def _is_inbound_visible(inbound) -> bool:
        if not inbound:
            return False
        return bool(inbound.enable) and bool(getattr(inbound, "show_in_app", 1))

    def _latest_visible_account_for_protocol(db, user_id: int, protocol: str):
        rows = _visible_accounts_for_protocol(db, user_id, protocol)
        return rows[0] if rows else (None, None)

    def _visible_accounts_for_protocol(db, user_id: int, protocol: str):
        variants = _protocol_variants(protocol)
        protocol_value = (protocol or "").strip().lower()
        if protocol_value == "vless":
            account_protocols = {"vless"}
        else:
            account_protocols = {"mixed", "http", "socks", "socks5"}
        accounts = (
            db.query(VpnAccount)
            .filter(
                VpnAccount.user_id == user_id,
                VpnAccount.protocol.in_(account_protocols),
                VpnAccount.status == "active",
            )
            .order_by(VpnAccount.id.desc())
            .all()
        )
        out: list[tuple[VpnAccount, SimpleNamespace]] = []
        for account in accounts:
            inbound, inbound_row, _panel = _resolve_account_inbound(db, account)
            if not inbound:
                continue
            if not inbound.port:
                continue
            inbound_protocol = (inbound.protocol or "").strip().lower()
            if inbound_protocol not in variants:
                continue
            if not _is_inbound_visible(inbound):
                continue
            out.append((account, inbound))
        return out

    def _protocol_visible_in_app(db, protocol: str) -> bool:
        variants = _protocol_variants(protocol)
        panel_row = (
            db.query(PanelInbound.id)
            .join(Panel, Panel.id == PanelInbound.panel_id)
            .filter(
                PanelInbound.protocol.in_(variants),
                PanelInbound.enabled == 1,
                PanelInbound.show_in_app == 1,
                PanelInbound.port.isnot(None),
                Panel.is_active == 1,
            )
            .order_by(PanelInbound.updated_at.desc(), PanelInbound.id.desc())
            .first()
        )
        if panel_row:
            return True
        return False

    def _service_status(inbound) -> dict:
        if not inbound:
            return {
                "ok": False,
                "configured": False,
                "port": None,
                "error": "Inbound not synced. Run /api/admin/sync-inbounds.",
            }
        panel_inbound_id = getattr(inbound, "panel_inbound_id", None)
        if panel_inbound_id is None:
            panel_inbound_id = getattr(inbound, "external_inbound_id", None)
        return {
            "ok": check_port("127.0.0.1", int(inbound.port)),
            "configured": True,
            "port": int(inbound.port),
            "panel_inbound_id": panel_inbound_id,
            "panel_id": getattr(inbound, "panel_id", None),
        }

    def _extract_clients_from_inbound(inbound) -> list[dict]:
        if not inbound:
            return []
        settings = inbound.settings if isinstance(inbound.settings, dict) else {}
        protocol_raw = (inbound.protocol or "").strip().lower()
        protocol = "mixed" if protocol_raw in {"mixed", "http", "socks", "socks5"} else protocol_raw

        def _as_list(value):
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return [value]
            if isinstance(value, str):
                try:
                    parsed = json.loads(value)
                except ValueError:
                    return []
                if isinstance(parsed, list):
                    return parsed
                if isinstance(parsed, dict):
                    return [parsed]
            return []

        raw_clients = _as_list(settings.get("clients"))
        raw_accounts = _as_list(settings.get("accounts"))
        source_items = [*raw_clients, *raw_accounts]
        if not source_items:
            return []

        out: list[dict] = []
        for client in source_items:
            if not isinstance(client, dict):
                continue
            identifier = (
                client.get("id")
                or client.get("email")
                or client.get("username")
                or client.get("user")
            )
            identifier = str(identifier).strip() if identifier is not None else ""
            if not identifier:
                continue

            label = (
                client.get("email")
                or client.get("remark")
                or client.get("username")
                or client.get("user")
                or identifier
            )
            secret = client.get("password") or client.get("pass")
            sub_id = client.get("subId") or client.get("subid")
            out.append(
                {
                    "identifier": identifier,
                    "label": str(label),
                    "secret": secret if isinstance(secret, str) else None,
                    "sub_id": str(sub_id) if sub_id is not None else None,
                    "protocol": protocol,
                    "raw": client,
                }
            )
        return out

    def _sync_single_inbound_from_panel(db, panel_item: dict, panel: Panel | None = None):
        panel_id_raw = panel_item.get("id")
        if panel_id_raw is None:
            raise ValueError("panel inbound item has no id")
        external_inbound_id = str(panel_id_raw)

        target_panel = panel
        if not target_panel:
            raise RuntimeError("Panel is required for inbound sync")

        panel_inbound = (
            db.query(PanelInbound)
            .filter(
                PanelInbound.panel_id == target_panel.id,
                PanelInbound.external_inbound_id == external_inbound_id,
            )
            .first()
        )
        if not panel_inbound:
            panel_inbound = PanelInbound(
                panel_id=target_panel.id,
                external_inbound_id=external_inbound_id,
                show_in_app=1,
            )
            db.add(panel_inbound)
            db.flush()

        panel_inbound.protocol = panel_item.get("protocol")
        panel_inbound.port = panel_item.get("port")
        panel_inbound.remark = panel_item.get("remark")
        panel_inbound.listen = panel_item.get("listen")
        panel_inbound.enabled = 1 if panel_item.get("enable", True) else 0
        panel_inbound.stream_settings = _safe_json(panel_item.get("streamSettings"))
        panel_inbound.settings = _safe_json(panel_item.get("settings"))
        panel_inbound.last_sync_at = utcnow()

        return panel_inbound

    def system_stats():
        vm = psutil.virtual_memory()
        du = psutil.disk_usage("/")
        return {
            "cpu_pct": psutil.cpu_percent(interval=0.05),
            "ram_used_pct": round(vm.percent, 1),
            "disk_used_pct": round(du.percent, 1),
            "uptime_s": int(psutil.boot_time() and (datetime.utcnow().timestamp() - psutil.boot_time())),
        }

    def _panels_status_payload(db, *, refresh: bool = False) -> tuple[list[dict], dict]:
        now = utcnow()
        rows = db.query(Panel).order_by(Panel.created_at.asc()).all()
        out: list[dict] = []
        healthy = 0
        degraded = 0
        down = 0

        for panel in rows:
            if refresh:
                panel_registry.health_check(db, panel)

            last_ok = _as_utc(panel.last_ok_at)
            age_sec = (now - last_ok).total_seconds() if last_ok else None
            color = (panel.health_status or "unknown").strip().lower()
            if age_sec is not None:
                if age_sec < 600:
                    color = "green"
                elif age_sec < 1800 and color != "red":
                    color = "yellow"
                elif age_sec >= 1800:
                    color = "red"
            if color not in {"green", "yellow", "red"}:
                color = "unknown"

            if color == "green":
                healthy += 1
            elif color == "yellow":
                degraded += 1
            elif color == "red":
                down += 1

            out.append(
                {
                    "id": panel.id,
                    "name": panel.name,
                    "provider": panel.provider,
                    "base_url": panel.base_url,
                    "region": panel.region,
                    "is_active": bool(panel.is_active),
                    "is_default": False,
                    "health_status": color,
                    "last_ok_at": panel.last_ok_at.isoformat() if panel.last_ok_at else None,
                    "error_message": panel.error_message,
                }
            )

        summary = {
            "healthy_count": healthy,
            "degraded_count": degraded,
            "down_count": down,
            "total_count": len(out),
        }
        return out, summary

    def _get_or_create_user_by_telegram_id(db, telegram_id: str) -> tuple[User, bool]:
        user = db.query(User).filter(User.telegram_id == telegram_id).first()
        if user:
            return user, False

        user = User(
            telegram_id=telegram_id,
            role=role_bindings.get(telegram_id, "user"),
        )
        db.add(user)
        db.flush()
        return user, True

    def _apply_admin_subscription_payload(db, user: User, body: dict):
        touches_subscription = any(
            key in body for key in ("extend_months", "status", "price_amount", "access_until")
        )
        sub = _latest_subscription(db, user.id)
        if touches_subscription and not sub:
            sub = Subscription(user_id=user.id, status="active")
            db.add(sub)
            db.flush()

        if sub and "extend_months" in body and str(body.get("extend_months")).strip() != "":
            try:
                months = int(body.get("extend_months"))
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "extend_months must be an integer"}), 400
            if months <= 0:
                return jsonify({"ok": False, "error": "extend_months must be > 0"}), 400

            now = utcnow()
            current_until = _as_utc(sub.access_until)
            base = current_until if current_until and current_until > now else now
            sub.access_until = base + timedelta(days=30 * months)
            sub.status = "active"

        if sub and "status" in body and body.get("status") not in (None, ""):
            status = str(body.get("status")).strip().lower()
            allowed_statuses = {"active", "lifetime", "expired", "paused", "canceled", "inactive"}
            if status not in allowed_statuses:
                return jsonify({"ok": False, "error": "invalid subscription status"}), 400
            sub.status = status

        if sub and "price_amount" in body:
            raw_price = body.get("price_amount")
            if raw_price in (None, ""):
                sub.price_amount = None
            else:
                try:
                    sub.price_amount = Decimal(str(raw_price))
                except (InvalidOperation, ValueError):
                    return jsonify({"ok": False, "error": "price_amount must be a number"}), 400

        if sub and "access_until" in body:
            raw_access_until = body.get("access_until")
            if raw_access_until in (None, ""):
                sub.access_until = None
            else:
                try:
                    parsed = datetime.fromisoformat(str(raw_access_until).replace("Z", "+00:00"))
                except ValueError:
                    return jsonify({"ok": False, "error": "access_until must be ISO datetime"}), 400
                sub.access_until = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

        if sub and (sub.status or "").strip().lower() == "lifetime":
            sub.access_until = None

        if "connections_limit" in body:
            raw_limit = body.get("connections_limit")
            profile = user.profile_data if isinstance(user.profile_data, dict) else {}
            if raw_limit in (None, ""):
                profile.pop("connections_limit", None)
            else:
                try:
                    limit = int(raw_limit)
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error": "connections_limit must be an integer"}), 400
                if limit < 0:
                    return jsonify({"ok": False, "error": "connections_limit must be >= 0"}), 400
                profile["connections_limit"] = limit
            user.profile_data = profile

        return None

    def _serialize_panel(panel: Panel) -> dict:
        return {
            "id": panel.id,
            "name": panel.name,
            "provider": panel.provider,
            "base_url": panel.base_url,
            "auth_type": panel.auth_type,
            "auth_secret_ref": panel.auth_secret_ref,
            "is_active": bool(panel.is_active),
            "is_default": False,
            "region": panel.region,
            "health_status": panel.health_status,
            "last_ok_at": panel.last_ok_at.isoformat() if panel.last_ok_at else None,
            "error_message": panel.error_message,
            "created_at": panel.created_at.isoformat() if panel.created_at else None,
            "updated_at": panel.updated_at.isoformat() if panel.updated_at else None,
        }

    return {
        "check_port": check_port,
        "_panel_host_port": _panel_host_port,
        "_panel_by_inbound_ref": _panel_by_inbound_ref,
        "_panel_inbound_snapshot": _panel_inbound_snapshot,
        "_resolve_account_inbound": _resolve_account_inbound,
        "_protocol_variants": _protocol_variants,
        "_inbound_for_protocol": _inbound_for_protocol,
        "_is_inbound_visible": _is_inbound_visible,
        "_latest_visible_account_for_protocol": _latest_visible_account_for_protocol,
        "_visible_accounts_for_protocol": _visible_accounts_for_protocol,
        "_protocol_visible_in_app": _protocol_visible_in_app,
        "_service_status": _service_status,
        "_extract_clients_from_inbound": _extract_clients_from_inbound,
        "_sync_single_inbound_from_panel": _sync_single_inbound_from_panel,
        "system_stats": system_stats,
        "_panels_status_payload": _panels_status_payload,
        "_get_or_create_user_by_telegram_id": _get_or_create_user_by_telegram_id,
        "_apply_admin_subscription_payload": _apply_admin_subscription_payload,
        "_serialize_panel": _serialize_panel,
    }

__all__ = ["build_admin_helpers"]
