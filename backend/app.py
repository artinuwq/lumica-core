import os

from flask import Flask, jsonify, request

from .db import Base, SessionLocal, engine
from .models import User
from .tg_auth import validate_init_data


def create_app():
    app = Flask(__name__)

    Base.metadata.create_all(bind=engine)

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.post("/api/tg/auth")
    def tg_auth():
        body = request.get_json(silent=True) or {}
        user_data = validate_init_data(body.get("initData", ""))
        if not user_data:
            return jsonify({"ok": False, "error": "Invalid initData"}), 401

        with SessionLocal() as session:
            telegram_id = str(user_data.get("id", ""))
            user = session.query(User).filter_by(telegram_id=telegram_id).first()
            if not user:
                user = User(telegram_id=telegram_id)
                session.add(user)

            user.username = user_data.get("username")
            user.first_name = user_data.get("first_name")
            user.last_name = user_data.get("last_name")
            session.commit()

        return jsonify({"ok": True, "user": user_data})

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "8000"))
    app.run(host=host, port=port)
