from __future__ import annotations


class EngineBase:
    @staticmethod
    def _compose_create_body(name: str) -> dict:
        return {"name": name}

    @staticmethod
    def _compose_update_body(id: str, name: str) -> dict:
        return {"id": id, "name": name}
