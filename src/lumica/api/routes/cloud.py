from __future__ import annotations

def register_cloud_routes(app, deps):
    # Transitional dependency injection while handlers are being migrated out
    # of shared app helper closures.
    globals().update(deps)

    @app.get("/api/cloud/list")
    def cloud_list():
        auth, err = _auth_context()
        if err:
            return err

        try:
            current_path = _normalize_cloud_path(request.args.get("path", "/"))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            folder = _resolve_cloud_folder(db, owner_user_id=auth["user_id"], path=current_path)
            if current_path != "/" and not folder:
                return jsonify({"ok": False, "error": "Folder not found"}), 404

            parent_id = folder.id if folder else None
            query = db.query(CloudNode).filter(CloudNode.owner_user_id == auth["user_id"])
            if parent_id is None:
                query = query.filter(CloudNode.parent_id.is_(None))
            else:
                query = query.filter(CloudNode.parent_id == parent_id)
            nodes = query.all()

            file_node_ids = [node.id for node in nodes if node.node_type == CLOUD_NODE_TYPE_FILE]
            files_by_node_id: dict[int, CloudFile] = {}
            if file_node_ids:
                file_rows = (
                    db.query(CloudFile)
                    .filter(
                        CloudFile.owner_user_id == auth["user_id"],
                        CloudFile.node_id.in_(file_node_ids),
                    )
                    .all()
                )
                files_by_node_id = {row.node_id: row for row in file_rows}

            folders: list[dict] = []
            files: list[dict] = []
            for node in nodes:
                payload = _cloud_node_to_payload(node, parent_path=current_path)
                if node.node_type == CLOUD_NODE_TYPE_FOLDER:
                    folders.append(payload)
                    continue

                file_row = files_by_node_id.get(node.id)
                payload["file"] = None
                if file_row:
                    payload["file"] = {
                        "file_id": file_row.id,
                        "original_name": file_row.original_name,
                        "extension": file_row.extension,
                        "mime_type": file_row.mime_type,
                        "size_bytes": file_row.size_bytes,
                        "chunk_size_bytes": file_row.chunk_size_bytes,
                        "chunk_count": file_row.chunk_count,
                        "checksum_sha256": file_row.checksum_sha256,
                        "status": file_row.status,
                        "error_text": file_row.error_text,
                        "created_at": file_row.created_at.isoformat() if file_row.created_at else None,
                        "updated_at": file_row.updated_at.isoformat() if file_row.updated_at else None,
                    }
                files.append(payload)

            folders.sort(key=lambda item: item["name"].lower())
            files.sort(key=lambda item: item["name"].lower())

            return jsonify(
                {
                    "ok": True,
                    "path": current_path,
                    "folders": folders,
                    "files": files,
                }
            )

    @app.post("/api/cloud/mkdir")
    def cloud_mkdir():
        auth, err = _auth_context()
        if err:
            return err

        body = request.get_json(silent=True) or {}
        create_parents = bool(body.get("create_parents"))

        target_path_raw = body.get("path")
        if target_path_raw:
            try:
                target_path = _normalize_cloud_path(str(target_path_raw))
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400
        else:
            try:
                parent_path = _normalize_cloud_path(body.get("parent_path", "/"))
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400
            name = _sanitize_cloud_name(body.get("name"))
            if not name:
                return jsonify({"ok": False, "error": "name is required"}), 400
            target_path = _cloud_join_path(parent_path, name)

        if target_path == "/":
            return jsonify({"ok": False, "error": "Cannot create root folder"}), 400

        try:
            parent_path, folder_name = _cloud_split_parent_path(target_path)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            parent_folder = _resolve_cloud_folder(
                db,
                owner_user_id=auth["user_id"],
                path=parent_path,
                create_missing=create_parents,
            )
            if parent_path != "/" and not parent_folder:
                return jsonify({"ok": False, "error": "Parent folder not found"}), 404

            parent_id = parent_folder.id if parent_folder else None
            existing = _find_cloud_child(
                db,
                owner_user_id=auth["user_id"],
                parent_id=parent_id,
                name=folder_name,
            )
            if existing:
                if existing.node_type != CLOUD_NODE_TYPE_FOLDER:
                    return jsonify({"ok": False, "error": "A file with the same name already exists"}), 409
                return jsonify(
                    {
                        "ok": True,
                        "existing": True,
                        "folder": _cloud_node_to_payload(existing, parent_path=parent_path),
                    }
                )

            folder = CloudNode(
                owner_user_id=auth["user_id"],
                parent_id=parent_id,
                node_type=CLOUD_NODE_TYPE_FOLDER,
                name=folder_name,
            )
            db.add(folder)
            db.commit()
            db.refresh(folder)
            return jsonify(
                {
                    "ok": True,
                    "existing": False,
                    "folder": _cloud_node_to_payload(folder, parent_path=parent_path),
                }
            )

    @app.post("/api/cloud/upload")
    def cloud_upload():
        auth, err = _auth_context()
        if err:
            return err

        file_storage = request.files.get("file")
        if not file_storage:
            return jsonify({"ok": False, "error": "file is required"}), 400

        try:
            target_path = _normalize_cloud_path(request.form.get("path", "/"))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        source_name = _sanitize_cloud_name(file_storage.filename or "")
        if not source_name:
            source_name = f"file-{utcnow().strftime('%Y%m%d-%H%M%S')}.bin"

        chunk_size = cloud_chunk_size_bytes()
        min_split_chunk_size = 512 * 1024
        try:
            min_split_chunk_kb = int(os.getenv("CLOUD_MIN_SPLIT_CHUNK_KB", "512"))
            min_split_chunk_size = max(64 * 1024, min_split_chunk_kb * 1024)
        except (TypeError, ValueError):
            min_split_chunk_size = 512 * 1024
        uploaded_total = 0
        uploaded_chunks = 0
        rolling_hash = hashlib.sha256()

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            folder = _resolve_cloud_folder(db, owner_user_id=auth["user_id"], path=target_path)
            if target_path != "/" and not folder:
                return jsonify({"ok": False, "error": "Target folder not found"}), 404

            parent_id = folder.id if folder else None
            final_name = _cloud_unique_child_name(
                db,
                owner_user_id=auth["user_id"],
                parent_id=parent_id,
                desired_name=source_name,
            )
            mime_type = file_storage.mimetype or mimetypes.guess_type(final_name)[0] or "application/octet-stream"
            suffix = Path(final_name).suffix

            node = CloudNode(
                owner_user_id=auth["user_id"],
                parent_id=parent_id,
                node_type=CLOUD_NODE_TYPE_FILE,
                name=final_name,
            )
            db.add(node)
            db.flush()

            cloud_file = CloudFile(
                node_id=node.id,
                owner_user_id=auth["user_id"],
                original_name=final_name,
                extension=suffix[1:].lower() if suffix.startswith(".") else None,
                mime_type=mime_type,
                size_bytes=0,
                chunk_size_bytes=0,
                chunk_count=0,
                status="uploading",
            )
            db.add(cloud_file)
            db.commit()
            db.refresh(node)
            db.refresh(cloud_file)

            try:
                while True:
                    chunk = file_storage.stream.read(chunk_size)
                    if not chunk:
                        break

                    rolling_hash.update(chunk)
                    pending_parts: list[bytes] = [chunk]
                    while pending_parts:
                        part = pending_parts.pop(0)
                        next_chunk_index = uploaded_chunks + 1
                        chunk_hash = hashlib.sha256(part).hexdigest()
                        part_name = f"{final_name}.part{next_chunk_index:06d}"
                        caption = f"cloud uid={auth['user_id']} file={cloud_file.id} chunk={next_chunk_index}"

                        try:
                            tg_meta = send_chunk_to_telegram(part, filename=part_name, caption=caption)
                        except TelegramStorageError as exc:
                            err_text = str(exc).lower()
                            is_timeout = ("timeout" in err_text) or ("timed out" in err_text)
                            can_split = len(part) > min_split_chunk_size
                            if is_timeout and can_split:
                                split_at = len(part) // 2
                                first = part[:split_at]
                                second = part[split_at:]
                                if first and second:
                                    pending_parts = [first, second, *pending_parts]
                                    continue
                            raise

                        uploaded_chunks = next_chunk_index
                        uploaded_total += len(part)
                        db.add(
                            CloudChunk(
                                file_id=cloud_file.id,
                                owner_user_id=auth["user_id"],
                                chunk_index=uploaded_chunks,
                                size_bytes=len(part),
                                checksum_sha256=chunk_hash,
                                tg_chat_id=tg_meta["chat_id"],
                                tg_message_id=tg_meta["message_id"],
                                tg_file_id=tg_meta["file_id"],
                                tg_file_unique_id=tg_meta["file_unique_id"] or None,
                                status="uploaded",
                            )
                        )
                        cloud_file.size_bytes = uploaded_total
                        cloud_file.chunk_size_bytes = chunk_size
                        cloud_file.chunk_count = uploaded_chunks
                        db.commit()

                cloud_file.status = "ready"
                cloud_file.error_text = None
                cloud_file.size_bytes = uploaded_total
                cloud_file.chunk_size_bytes = chunk_size if uploaded_chunks else 0
                cloud_file.chunk_count = uploaded_chunks
                cloud_file.checksum_sha256 = rolling_hash.hexdigest()
                db.commit()

                return jsonify(
                    {
                        "ok": True,
                        "path": _cloud_join_path(target_path, final_name),
                        "node_id": node.id,
                        "file": {
                            "file_id": cloud_file.id,
                            "name": final_name,
                            "mime_type": cloud_file.mime_type,
                            "size_bytes": cloud_file.size_bytes,
                            "chunk_size_bytes": cloud_file.chunk_size_bytes,
                            "chunk_count": cloud_file.chunk_count,
                            "checksum_sha256": cloud_file.checksum_sha256,
                            "status": cloud_file.status,
                        },
                    }
                )
            except TelegramStorageError as exc:
                db.rollback()
                failed = (
                    db.query(CloudFile)
                    .filter(
                        CloudFile.id == cloud_file.id,
                        CloudFile.owner_user_id == auth["user_id"],
                    )
                    .first()
                )
                if failed:
                    failed.status = "failed"
                    failed.error_text = str(exc)[:500]
                    failed.size_bytes = uploaded_total
                    failed.chunk_size_bytes = chunk_size if uploaded_chunks else 0
                    failed.chunk_count = uploaded_chunks
                    failed.checksum_sha256 = rolling_hash.hexdigest() if uploaded_total else None
                    db.commit()
                return jsonify({"ok": False, "error": f"Telegram storage error: {exc}"}), 502
            except Exception as exc:
                app.logger.exception("Cloud upload failed")
                db.rollback()
                failed = (
                    db.query(CloudFile)
                    .filter(
                        CloudFile.id == cloud_file.id,
                        CloudFile.owner_user_id == auth["user_id"],
                    )
                    .first()
                )
                if failed:
                    failed.status = "failed"
                    failed.error_text = str(exc)[:500]
                    failed.size_bytes = uploaded_total
                    failed.chunk_size_bytes = chunk_size if uploaded_chunks else 0
                    failed.chunk_count = uploaded_chunks
                    failed.checksum_sha256 = rolling_hash.hexdigest() if uploaded_total else None
                    db.commit()
                detail = str(exc).strip() or "unknown error"
                return jsonify({"ok": False, "error": f"Upload failed: {detail[:300]}"}), 500

    @app.get("/api/cloud/files/<int:file_id>/download")
    def cloud_download(file_id: int):
        auth, err = _auth_context()
        if err:
            return err
        inline_raw = str(request.args.get("inline", "")).strip().lower()
        inline_mode = inline_raw in {"1", "true", "yes", "on"}

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            cloud_file = (
                db.query(CloudFile)
                .filter(
                    CloudFile.id == file_id,
                    CloudFile.owner_user_id == auth["user_id"],
                )
                .first()
            )
            if not cloud_file:
                return jsonify({"ok": False, "error": "File not found"}), 404
            if cloud_file.status != "ready":
                return jsonify({"ok": False, "error": "File is not ready for download"}), 409

            chunks = (
                db.query(CloudChunk)
                .filter(
                    CloudChunk.file_id == cloud_file.id,
                    CloudChunk.owner_user_id == auth["user_id"],
                )
                .order_by(CloudChunk.chunk_index.asc())
                .all()
            )
            if len(chunks) != int(cloud_file.chunk_count or 0):
                return jsonify({"ok": False, "error": "File chunks are incomplete"}), 409

            file_name = cloud_file.original_name or f"file-{cloud_file.id}.bin"
            mime_type = cloud_file.mime_type or "application/octet-stream"
            size_bytes = int(cloud_file.size_bytes or 0)
            tg_file_ids = [str(chunk.tg_file_id) for chunk in chunks]

        def _stream():
            for tg_file_id in tg_file_ids:
                for piece in iter_telegram_file_bytes(tg_file_id):
                    yield piece

        response = Response(stream_with_context(_stream()), mimetype=mime_type)
        disposition = "inline" if inline_mode else "attachment"
        response.headers["Content-Disposition"] = f"{disposition}; filename*=UTF-8''{quote(file_name)}"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Cloud-File-Id"] = str(file_id)
        if size_bytes >= 0:
            response.headers["Content-Length"] = str(size_bytes)
        return response

    @app.delete("/api/cloud/nodes/<int:node_id>")
    def cloud_delete_node(node_id: int):
        auth, err = _auth_context()
        if err:
            return err

        message_ids: list[int] = []

        with SessionLocal() as db:
            if not _cloud_visibility_enabled(db):
                return jsonify({"ok": False, "error": "Cloud feature is disabled"}), 403

            node = (
                db.query(CloudNode)
                .filter(
                    CloudNode.id == node_id,
                    CloudNode.owner_user_id == auth["user_id"],
                )
                .first()
            )
            if not node:
                return jsonify({"ok": False, "error": "Node not found"}), 404

            if node.node_type == CLOUD_NODE_TYPE_FOLDER:
                has_children = (
                    db.query(CloudNode.id)
                    .filter(
                        CloudNode.owner_user_id == auth["user_id"],
                        CloudNode.parent_id == node.id,
                    )
                    .first()
                )
                if has_children:
                    return jsonify({"ok": False, "error": "Folder is not empty"}), 409

            if node.node_type == CLOUD_NODE_TYPE_FILE and node.file:
                message_ids = [chunk.tg_message_id for chunk in node.file.chunks if chunk.tg_message_id]

            db.delete(node)
            db.commit()

        for message_id in message_ids:
            delete_telegram_message(message_id)

        return jsonify({"ok": True, "deleted_node_id": node_id})

__all__ = ["register_cloud_routes"]
