from __future__ import annotations

def build_vpn_helpers(deps):
    # Transitional dependency injection: helpers still depend on
    # legacy names while extraction to service classes continues.
    globals().update(deps)

    def _generate_panel_sub_id(length: int = 16) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(secrets.choice(alphabet) for _ in range(max(8, length)))

    def _decode_subscription_payload(raw_text: str) -> str:
        text = (raw_text or "").strip()
        if not text:
            return ""
        if "://" in text:
            return text

        compact = "".join(text.split())
        if not compact:
            return ""
        pad = len(compact) % 4
        if pad:
            compact += "=" * (4 - pad)

        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(compact.encode("utf-8"))
            except Exception:
                continue
            as_text = decoded.decode("utf-8", errors="ignore").strip()
            if "://" in as_text:
                return as_text
        return text

    def _load_subscription_links(subscription_url: str, *, quiet: bool = False) -> list[str]:
        url = str(subscription_url or "").strip()
        if not url:
            return []
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return []

        try:
            response = requests.get(url, timeout=8)
            response.raise_for_status()
            payload = _decode_subscription_payload(response.text or "")
        except Exception as exc:
            if not quiet:
                app.logger.warning("subscription fetch failed for %s: %s", url, exc)
            return []

        links: list[str] = []
        for line in payload.splitlines():
            item = line.strip()
            if not item or "://" not in item:
                continue
            links.append(item)
        return links

    def _vless_identifier_from_url(link: str) -> str:
        value = str(link or "").strip()
        if not value.lower().startswith("vless://"):
            return ""
        rest = value[len("vless://") :]
        userinfo = rest.split("@", 1)[0] if "@" in rest else ""
        return unquote(userinfo).strip().lower()

    def _pick_vless_from_subscription(links: list[str], identifier: str | None) -> str | None:
        if not links:
            return None
        wanted = str(identifier or "").strip().lower()
        vless_links = [item for item in links if str(item).strip().lower().startswith("vless://")]
        if not vless_links:
            return None
        if wanted:
            for link in vless_links:
                if _vless_identifier_from_url(link) == wanted:
                    return link
        return vless_links[0]

    def _normalize_vless_client_name(label: str | None, identifier: str | None) -> str:
        value = str(label or "").strip()
        if not value:
            value = str(identifier or "").strip()
        if not value:
            return "client"

        low = value.lower()
        for suffix in ("-main", "_main", " main"):
            if low.endswith(suffix):
                value = value[: len(value) - len(suffix)].strip(" -_")
                break

        return value or "client"

    def _apply_vless_display_name(link: str | None, label: str | None, identifier: str | None) -> str | None:
        value = str(link or "").strip()
        if not value:
            return None
        if not value.lower().startswith("vless://"):
            return value

        client_name = _normalize_vless_client_name(label, identifier)
        display_name = f"Lumica - {client_name}"
        base = value.split("#", 1)[0]
        return f"{base}#{quote(display_name, safe='')}"

    def _build_subscription_urls(sub_id: str | None, explicit_url: str | None = None) -> list[str]:
        sid = str(sub_id or "").strip()
        sid_quoted = quote(sid) if sid else ""
        urls: list[str] = []

        def _append_url(raw: str | None):
            value = str(raw or "").strip()
            if not value:
                return
            parsed_value = urlparse(value)
            if parsed_value.scheme not in {"http", "https"}:
                return
            if value not in urls:
                urls.append(value)

        _append_url(explicit_url)

        public_base = os.getenv("PANEL_PUBLIC_BASE_URL", "").strip().rstrip("/")
        subscription_base = os.getenv("PANEL_SUBSCRIPTION_BASE_URL", "").strip().rstrip("/")
        tpl = os.getenv("PANEL_SUBSCRIPTION_URL_TEMPLATE", "").strip()
        if tpl:
            for base_url in (subscription_base, public_base, ""):
                try:
                    _append_url(tpl.format(sub_id=sid, base_url=base_url))
                except Exception as exc:
                    app.logger.warning("invalid PANEL_SUBSCRIPTION_URL_TEMPLATE: %s", exc)
                    break

        if sid:
            for base_url in (subscription_base, public_base):
                if not base_url:
                    continue
                _append_url(f"{base_url}/sub/{sid_quoted}")
                _append_url(f"{base_url}/subcrp/{sid_quoted}")

            panel_base = os.getenv("PANEL_BASE_URL", "").strip()
            parsed_base = urlparse(panel_base)
            if parsed_base.scheme in {"http", "https"} and parsed_base.netloc:
                root = f"{parsed_base.scheme}://{parsed_base.netloc}"
                _append_url(f"{root}/sub/{sid_quoted}")
                _append_url(f"{root}/subcrp/{sid_quoted}")

            public_host = os.getenv("PUBLIC_VPN_HOST", "").strip()
            sub_port = os.getenv("PANEL_SUBSCRIPTION_PORT", "").strip()
            if public_host and sub_port:
                _append_url(f"http://{public_host}:{sub_port}/sub/{sid_quoted}")
                _append_url(f"http://{public_host}:{sub_port}/subcrp/{sid_quoted}")
                _append_url(f"https://{public_host}:{sub_port}/sub/{sid_quoted}")
                _append_url(f"https://{public_host}:{sub_port}/subcrp/{sid_quoted}")

        return urls

    def _normalize_account_protocol(raw_protocol: str | None) -> str:
        value = (raw_protocol or "").strip().lower()
        return {
            "vless": "vless",
            "mixed": "mixed",
            "http": "mixed",
            "socks": "mixed",
            "socks5": "mixed",
        }.get(value, value)

    def _upsert_vpn_account(
        db,
        *,
        user_id: int,
        panel_inbound_ref_id: int,
        protocol: str,
        identifier: str,
        label: str | None = None,
        secret: str | None = None,
        sub_id: str | None = None,
    ) -> VpnAccount:
        normalized_protocol = _normalize_account_protocol(protocol)
        if normalized_protocol not in {"vless", "mixed"}:
            raise ValueError("protocol must be vless or mixed")

        query = (
            db.query(VpnAccount)
            .filter(
                VpnAccount.user_id == int(user_id),
                VpnAccount.protocol == normalized_protocol,
                VpnAccount.identifier == identifier,
                VpnAccount.panel_inbound_ref_id == int(panel_inbound_ref_id),
            )
        )
        account = query.order_by(VpnAccount.id.desc()).first()
        if not account:
            account = VpnAccount(user_id=int(user_id), protocol=normalized_protocol)
            db.add(account)

        meta = account.meta_json if isinstance(account.meta_json, dict) else {}
        if sub_id:
            meta["sub_id"] = str(sub_id)

        panel_inbound = db.query(PanelInbound).filter(PanelInbound.id == int(panel_inbound_ref_id)).first()
        try:
            account.panel_inbound_id = int(panel_inbound.external_inbound_id) if panel_inbound else None
        except (TypeError, ValueError):
            account.panel_inbound_id = None
        account.panel_inbound_ref_id = int(panel_inbound_ref_id)
        account.identifier = identifier
        account.label = label or identifier
        account.secret = secret if normalized_protocol == "mixed" else None
        account.meta_json = meta
        account.status = "active"
        return account

    def _serialize_pending_binding(db, row: PendingBinding) -> dict:
        panel_inbound, panel = _panel_by_inbound_ref(db, row.panel_inbound_ref_id) if row.panel_inbound_ref_id else (None, None)
        panel_inbound_id_value = None
        if panel_inbound:
            try:
                panel_inbound_id_value = int(panel_inbound.external_inbound_id)
            except (TypeError, ValueError):
                panel_inbound_id_value = None
        meta = row.meta_json if isinstance(row.meta_json, dict) else {}
        return {
            "id": row.id,
            "telegram_id": row.telegram_id,
            "status": row.status,
            "protocol": row.protocol,
            "panel_inbound_id": panel_inbound_id_value,
            "panel_inbound_ref_id": row.panel_inbound_ref_id,
            "panel_id": panel.id if panel else None,
            "panel_name": panel.name if panel else None,
            "inbound_remark": panel_inbound.remark if panel_inbound else None,
            "inbound_port": panel_inbound.port if panel_inbound else None,
            "identifier": row.identifier,
            "label": row.label,
            "sub_id": meta.get("sub_id"),
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "applied_at": row.applied_at.isoformat() if row.applied_at else None,
            "applied_user_id": row.applied_user_id,
        }

    def _apply_pending_bindings_for_user(db, user: User) -> int:
        if not user or not user.telegram_id:
            return 0

        pending_rows = (
            db.query(PendingBinding)
            .filter(
                PendingBinding.telegram_id == str(user.telegram_id),
                PendingBinding.status == "pending",
            )
            .order_by(PendingBinding.id.asc())
            .all()
        )
        if not pending_rows:
            return 0

        applied = 0
        for row in pending_rows:
            if not row.panel_inbound_ref_id:
                continue
            panel_inbound, _panel = _panel_by_inbound_ref(db, row.panel_inbound_ref_id)
            if not panel_inbound:
                continue

            sub_id = None
            if isinstance(row.meta_json, dict):
                sub_id = row.meta_json.get("sub_id")

            try:
                _upsert_vpn_account(
                    db,
                    user_id=user.id,
                    panel_inbound_ref_id=panel_inbound.id,
                    protocol=row.protocol,
                    identifier=row.identifier,
                    label=row.label,
                    secret=row.secret,
                    sub_id=sub_id,
                )
            except ValueError:
                # Invalid protocol should not block remaining rows.
                continue

            row.status = "applied"
            row.applied_user_id = user.id
            row.applied_at = utcnow()
            applied += 1

        return applied

    def _normalize_selection_strategy(raw_value: str | None) -> str:
        value = str(raw_value or "").strip().lower()
        allowed = {"manual", "region_first", "least_loaded", "priority_order"}
        return value if value in allowed else "priority_order"

    def _load_default_selection_strategy(db) -> str:
        value = SettingsManager(db).get_value("vpn.selection.default_strategy", default="priority_order")
        return _normalize_selection_strategy(str(value or "priority_order"))

    def _group_by_key(db, group_key: str) -> InboundGroup | None:
        return db.query(InboundGroup).filter(InboundGroup.key == group_key).first()

    def _ensure_user_connection(db, user_id: int, group_key: str) -> UserConnection | None:
        group = _group_by_key(db, group_key)
        if not group:
            return None
        row = (
            db.query(UserConnection)
            .filter(UserConnection.user_id == int(user_id), UserConnection.group_id == int(group.id))
            .first()
        )
        if row:
            return row
        row = UserConnection(
            user_id=int(user_id),
            group_id=int(group.id),
            selected_member_id=None,
            selection_strategy=_load_default_selection_strategy(db),
        )
        db.add(row)
        db.flush()
        return row

    def _resolve_account_member(db, account: VpnAccount, group_key: str):
        group = _group_by_key(db, group_key)
        if not group:
            return None, None, None
        inbound_snapshot, panel_inbound, panel = _resolve_account_inbound(db, account)
        if not inbound_snapshot:
            return None, None, None
        if not panel_inbound:
            return inbound_snapshot, None, panel

        member = (
            db.query(InboundGroupMember)
            .filter(
                InboundGroupMember.group_id == group.id,
                InboundGroupMember.panel_inbound_id == panel_inbound.id,
            )
            .first()
        )
        if not member:
            member = InboundGroupMember(
                group_id=group.id,
                panel_inbound_id=panel_inbound.id,
                label=panel_inbound.remark,
                priority=100,
                is_active=1,
            )
            db.add(member)
            db.flush()
        if not panel:
            panel = db.query(Panel).filter(Panel.id == panel_inbound.panel_id).first()
        return inbound_snapshot, member, panel

    def _account_candidates_for_protocol(db, user_id: int, protocol: str) -> list[dict]:
        rows = _visible_accounts_for_protocol(db, user_id, protocol)
        group_key = protocol_to_group_key(protocol)
        out: list[dict] = []
        for account, inbound in rows:
            member = None
            panel = None
            inbound_snapshot = inbound
            if group_key:
                resolved_inbound, resolved_member, resolved_panel = _resolve_account_member(db, account, group_key)
                if resolved_inbound:
                    inbound_snapshot = resolved_inbound
                member = resolved_member
                panel = resolved_panel

            out.append(
                {
                    "account": account,
                    "inbound": inbound_snapshot,
                    "member_id": member.id if member else None,
                    "priority": member.priority if member else 999999,
                    "region": panel.region if panel else None,
                    "panel_id": panel.id if panel else None,
                    "panel_name": panel.name if panel else None,
                }
            )
        return out

    def _pick_candidate_by_strategy(db, candidates: list[dict], strategy: str, user: User | None = None) -> dict | None:
        if not candidates:
            return None
        normalized = _normalize_selection_strategy(strategy)

        if normalized == "least_loaded":
            load_by_ref: dict[int, int] = {}
            ref_ids = [int(item["account"].panel_inbound_ref_id) for item in candidates if item["account"].panel_inbound_ref_id]
            if ref_ids:
                rows = (
                    db.query(VpnAccount.panel_inbound_ref_id, text("COUNT(*)"))
                    .filter(VpnAccount.panel_inbound_ref_id.in_(ref_ids), VpnAccount.status == "active")
                    .group_by(VpnAccount.panel_inbound_ref_id)
                    .all()
                )
                load_by_ref = {int(ref_id): int(cnt) for ref_id, cnt in rows if ref_id is not None}

            return sorted(
                candidates,
                key=lambda item: (
                    load_by_ref.get(int(item["account"].panel_inbound_ref_id or 0), 0),
                    int(item.get("priority") or 999999),
                    int(item["account"].id),
                ),
            )[0]

        if normalized == "region_first":
            user_region = None
            profile = user.profile_data if user and isinstance(user.profile_data, dict) else {}
            if profile:
                user_region = str(profile.get("region") or "").strip().lower() or None
            return sorted(
                candidates,
                key=lambda item: (
                    0 if user_region and str(item.get("region") or "").strip().lower() == user_region else 1,
                    int(item.get("priority") or 999999),
                    int(item["account"].id),
                ),
            )[0]

        # manual and priority_order share deterministic fallback ordering.
        return sorted(
            candidates,
            key=lambda item: (int(item.get("priority") or 999999), int(item["account"].id)),
        )[0]

    def _resolve_selected_candidate(db, user_id: int, protocol: str) -> tuple[list[dict], dict | None, str, int | None]:
        group_key = protocol_to_group_key(protocol)
        candidates = _account_candidates_for_protocol(db, user_id, protocol)
        if not group_key:
            return candidates, (candidates[0] if candidates else None), "priority_order", None

        user = db.query(User).filter(User.id == int(user_id)).first()
        user_conn = _ensure_user_connection(db, user_id, group_key)
        strategy = _normalize_selection_strategy(user_conn.selection_strategy if user_conn else _load_default_selection_strategy(db))
        selected = None
        if user_conn and user_conn.selected_member_id:
            selected = next((item for item in candidates if item.get("member_id") == user_conn.selected_member_id), None)
        if not selected:
            selected = _pick_candidate_by_strategy(db, candidates, strategy, user=user)

        selected_member_id = selected.get("member_id") if selected else None
        if user_conn:
            # Keep persisted selection stable if manual selection was not explicitly set.
            if user_conn.selected_member_id is None and selected_member_id is not None:
                user_conn.selected_member_id = selected_member_id

        if selected:
            candidates = [selected, *[item for item in candidates if item is not selected]]
        return candidates, selected, strategy, selected_member_id

    return {
        "_generate_panel_sub_id": _generate_panel_sub_id,
        "_decode_subscription_payload": _decode_subscription_payload,
        "_load_subscription_links": _load_subscription_links,
        "_vless_identifier_from_url": _vless_identifier_from_url,
        "_pick_vless_from_subscription": _pick_vless_from_subscription,
        "_normalize_vless_client_name": _normalize_vless_client_name,
        "_apply_vless_display_name": _apply_vless_display_name,
        "_build_subscription_urls": _build_subscription_urls,
        "_normalize_account_protocol": _normalize_account_protocol,
        "_upsert_vpn_account": _upsert_vpn_account,
        "_serialize_pending_binding": _serialize_pending_binding,
        "_apply_pending_bindings_for_user": _apply_pending_bindings_for_user,
        "_normalize_selection_strategy": _normalize_selection_strategy,
        "_load_default_selection_strategy": _load_default_selection_strategy,
        "_group_by_key": _group_by_key,
        "_ensure_user_connection": _ensure_user_connection,
        "_resolve_account_member": _resolve_account_member,
        "_account_candidates_for_protocol": _account_candidates_for_protocol,
        "_pick_candidate_by_strategy": _pick_candidate_by_strategy,
        "_resolve_selected_candidate": _resolve_selected_candidate,
    }

__all__ = ["build_vpn_helpers"]
