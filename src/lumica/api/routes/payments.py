from __future__ import annotations

PAYMENT_INSTRUCTIONS_SETTING_KEY = "payments.instructions"


def register_payment_routes(app, deps):
    # Transitional dependency injection, same pattern as the other route modules.
    globals().update(deps)

    from lumica.domain.models import Group, Payment, Subscription
    from lumica.services import groups as group_service
    from lumica.services import payments as payment_service
    from lumica.services.settings import SettingsManager

    def _serialize(payment: Payment) -> dict:
        return {
            "id": payment.id,
            "user_id": payment.user_id,
            "group_id": payment.group_id,
            "amount": str(payment.amount) if payment.amount is not None else None,
            "status": payment.status,
            "confirmed_by": payment.confirmed_by,
            "confirmed_at": payment.confirmed_at.isoformat() if payment.confirmed_at else None,
            "reject_reason": payment.reject_reason,
            "created_at": payment.created_at.isoformat() if payment.created_at else None,
            "subscription_ids": [s.id for s in payment.subscriptions],
        }

    def _serialize_subscription(subscription: Subscription) -> dict:
        return {
            "id": subscription.id,
            "user_id": subscription.user_id,
            "status": subscription.status,
            "access_until": subscription.access_until.isoformat() if subscription.access_until else None,
            "price_amount": str(subscription.price_amount) if subscription.price_amount is not None else None,
            "total_price": str(subscription.total_price) if subscription.total_price is not None else None,
        }

    def _find_payment(db, payment_id: int):
        payment = db.query(Payment).filter(Payment.id == payment_id).first()
        if not payment:
            return None, (jsonify({"ok": False, "error": "Платёж не найден"}), 404)
        return payment, None

    @app.get("/api/payments/instructions")
    def payment_instructions_route():
        auth, err = _auth_context()
        if err:
            return err
        with SessionLocal() as db:
            value = SettingsManager(db).get_value(PAYMENT_INSTRUCTIONS_SETTING_KEY, default={})
        if not isinstance(value, dict):
            value = {}
        return jsonify({"ok": True, "data": value})

    @app.post("/api/payments/instructions")
    def set_payment_instructions_route():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        payload = {
            "card_number": body.get("card_number"),
            "recipient": body.get("recipient"),
            "text": body.get("text"),
        }
        with SessionLocal() as db:
            SettingsManager(db).set_setting(
                PAYMENT_INSTRUCTIONS_SETTING_KEY, payload, description="Реквизиты и текст для оплаты"
            )
            db.commit()
        return jsonify({"ok": True, "data": payload})

    @app.post("/api/payments")
    def create_payment_route():
        auth, err = _auth_context()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        subscription_id_raw = body.get("subscription_id") or body.get("draft_id")
        try:
            subscription_id = int(subscription_id_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "subscription_id must be an integer"}), 400

        with SessionLocal() as db:
            try:
                payment = payment_service.create_payment(db, user_id=auth["user_id"], subscription_id=subscription_id)
                db.commit()
            except payment_service.PaymentError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(payment)}), 201

    @app.post("/api/groups/<int:group_id>/payments")
    def create_group_payment_route(group_id):
        """Групповой платёж: платит только администратор группы (тот же
        пользователь, что вызывает эндпоинт), сразу за несколько подписок
        участников группы."""
        auth, err = _auth_context()
        if err:
            return err
        body = request.get_json(silent=True) or {}
        raw_ids = body.get("subscription_ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            return jsonify({"ok": False, "error": "subscription_ids must be a non-empty list"}), 400
        try:
            subscription_ids = [int(x) for x in raw_ids]
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "subscription_ids must be integers"}), 400

        with SessionLocal() as db:
            try:
                payment = payment_service.create_group_payment(
                    db, admin_user_id=auth["user_id"], group_id=group_id, subscription_ids=subscription_ids
                )
                db.commit()
            except payment_service.PaymentError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(payment)}), 201

    @app.get("/api/payments/mine")
    def my_payments_route():
        auth, err = _auth_context()
        if err:
            return err
        with SessionLocal() as db:
            items = (
                db.query(Payment)
                .filter(Payment.user_id == auth["user_id"])
                .order_by(Payment.created_at.desc())
                .all()
            )
            return jsonify({"ok": True, "data": [_serialize(p) for p in items]})

    @app.get("/api/payments")
    def list_payments_route():
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        status_filter = (request.args.get("status") or "").strip() or None
        with SessionLocal() as db:
            query = db.query(Payment).order_by(Payment.created_at.desc())
            if status_filter:
                query = query.filter(Payment.status == status_filter)
            items = [_serialize(p) for p in query.limit(200).all()]
        return jsonify({"ok": True, "data": items})

    @app.post("/api/payments/<int:payment_id>/confirm")
    def confirm_payment_route(payment_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        with SessionLocal() as db:
            payment, err = _find_payment(db, payment_id)
            if err:
                return err
            try:
                subscriptions = payment_service.confirm_payment(db, payment, staff_user_id=auth["user_id"])
                db.commit()
            except payment_service.PaymentError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify(
                {
                    "ok": True,
                    "data": {
                        "payment": _serialize(payment),
                        "subscriptions": [_serialize_subscription(s) for s in subscriptions],
                    },
                }
            )

    @app.post("/api/payments/<int:payment_id>/reject")
    def reject_payment_route(payment_id):
        auth, err = _auth_context(require_role="admin")
        if err:
            return err
        body = request.get_json(silent=True) or {}
        with SessionLocal() as db:
            payment, err = _find_payment(db, payment_id)
            if err:
                return err
            try:
                payment_service.reject_payment(
                    db, payment, staff_user_id=auth["user_id"], reason=body.get("reason")
                )
                db.commit()
            except payment_service.PaymentError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(payment)})

    @app.post("/api/payments/<int:payment_id>/cancel")
    def cancel_payment_route(payment_id):
        auth, err = _auth_context()
        if err:
            return err
        with SessionLocal() as db:
            payment, err = _find_payment(db, payment_id)
            if err:
                return err
            is_owner = payment.user_id == auth["user_id"]
            if not is_owner and not _role_allows(auth.get("role"), "admin"):
                return jsonify({"ok": False, "error": "Forbidden"}), 403
            try:
                payment_service.cancel_payment(db, payment)
                db.commit()
            except payment_service.PaymentError as exc:
                db.rollback()
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify({"ok": True, "data": _serialize(payment)})


__all__ = ["register_payment_routes", "PAYMENT_INSTRUCTIONS_SETTING_KEY"]
