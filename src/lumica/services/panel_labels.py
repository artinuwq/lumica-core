"""Короткие подписи серверов (панелей): «De», «Fl», «Nl»."""

from __future__ import annotations


def server_code(panel) -> str | None:
    """Две буквы сервера: регион «de» -> «De», иначе начало названия."""
    if panel is None:
        return None
    for source in (getattr(panel, "region", None), getattr(panel, "name", None)):
        letters = "".join(ch for ch in str(source or "") if ch.isalnum())[:2]
        if letters:
            return letters.capitalize()
    return None


__all__ = ["server_code"]
