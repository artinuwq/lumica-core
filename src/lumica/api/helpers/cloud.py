from __future__ import annotations

def build_cloud_helpers(deps):
    # Transitional dependency injection: helpers still depend on
    # legacy names while extraction to service classes continues.
    globals().update(deps)

    def _cloud_visibility_enabled(db) -> bool:
        raw = SettingsManager(db).get_value(
            CLOUD_VISIBILITY_KEY,
            default=os.getenv("CLOUD_VISIBILITY", "true"),
        )
        return to_bool(raw, default=True)

    def _sanitize_cloud_name(raw_name: str | None) -> str:
        value = (raw_name or "").replace("\\", "/").strip()
        value = value.split("/")[-1].strip()
        if not value or value in {".", ".."}:
            return ""
        return value[:255]

    def _normalize_cloud_path(raw_path: str | None) -> str:
        value = (raw_path or "/").replace("\\", "/").strip()
        if not value:
            return "/"
        if not value.startswith("/"):
            value = f"/{value}"
        parts: list[str] = []
        for part in value.split("/"):
            part = part.strip()
            if not part or part == ".":
                continue
            if part == "..":
                raise ValueError("Path traversal is not allowed")
            safe = _sanitize_cloud_name(part)
            if not safe:
                raise ValueError("Invalid path segment")
            parts.append(safe)
        if not parts:
            return "/"
        return "/" + "/".join(parts)

    def _cloud_path_parts(path: str) -> list[str]:
        if path == "/":
            return []
        return [part for part in path.strip("/").split("/") if part]

    def _cloud_join_path(parent_path: str, child_name: str) -> str:
        if parent_path == "/":
            return f"/{child_name}"
        return f"{parent_path}/{child_name}"

    def _cloud_split_parent_path(path: str) -> tuple[str, str]:
        parts = _cloud_path_parts(path)
        if not parts:
            raise ValueError("Path must not be root")
        name = parts[-1]
        parent_parts = parts[:-1]
        parent_path = "/" + "/".join(parent_parts) if parent_parts else "/"
        return parent_path, name

    def _find_cloud_child(
        db,
        *,
        owner_user_id: int,
        parent_id: int | None,
        name: str,
    ) -> CloudNode | None:
        query = db.query(CloudNode).filter(
            CloudNode.owner_user_id == owner_user_id,
            CloudNode.name == name,
        )
        if parent_id is None:
            query = query.filter(CloudNode.parent_id.is_(None))
        else:
            query = query.filter(CloudNode.parent_id == parent_id)
        return query.first()

    def _resolve_cloud_folder(
        db,
        *,
        owner_user_id: int,
        path: str,
        create_missing: bool = False,
    ) -> CloudNode | None:
        if path == "/":
            return None

        parent_id: int | None = None
        current: CloudNode | None = None
        for part in _cloud_path_parts(path):
            child = _find_cloud_child(db, owner_user_id=owner_user_id, parent_id=parent_id, name=part)
            if child and child.node_type != CLOUD_NODE_TYPE_FOLDER:
                return None
            if not child:
                if not create_missing:
                    return None
                child = CloudNode(
                    owner_user_id=owner_user_id,
                    parent_id=parent_id,
                    node_type=CLOUD_NODE_TYPE_FOLDER,
                    name=part,
                )
                db.add(child)
                db.flush()
            current = child
            parent_id = child.id
        return current

    def _cloud_unique_child_name(
        db,
        *,
        owner_user_id: int,
        parent_id: int | None,
        desired_name: str,
    ) -> str:
        safe_name = _sanitize_cloud_name(desired_name)
        if not safe_name:
            safe_name = f"file-{utcnow().strftime('%Y%m%d-%H%M%S')}.bin"

        stem = Path(safe_name).stem
        suffix = Path(safe_name).suffix
        candidate = safe_name
        idx = 1
        while _find_cloud_child(db, owner_user_id=owner_user_id, parent_id=parent_id, name=candidate):
            candidate = f"{stem} ({idx}){suffix}"
            idx += 1
        return candidate

    def _cloud_node_to_payload(node: CloudNode, *, parent_path: str) -> dict:
        return {
            "node_id": node.id,
            "type": node.node_type,
            "name": node.name,
            "path": _cloud_join_path(parent_path, node.name),
            "created_at": node.created_at.isoformat() if node.created_at else None,
            "updated_at": node.updated_at.isoformat() if node.updated_at else None,
        }

    return {
        "_cloud_visibility_enabled": _cloud_visibility_enabled,
        "_sanitize_cloud_name": _sanitize_cloud_name,
        "_normalize_cloud_path": _normalize_cloud_path,
        "_cloud_path_parts": _cloud_path_parts,
        "_cloud_join_path": _cloud_join_path,
        "_cloud_split_parent_path": _cloud_split_parent_path,
        "_find_cloud_child": _find_cloud_child,
        "_resolve_cloud_folder": _resolve_cloud_folder,
        "_cloud_unique_child_name": _cloud_unique_child_name,
        "_cloud_node_to_payload": _cloud_node_to_payload,
    }

__all__ = ["build_cloud_helpers"]
