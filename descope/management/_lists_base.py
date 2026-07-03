from __future__ import annotations

from typing import Any, List, Optional


class ListsBase:
    @staticmethod
    def _compose_create_body(name: str, description: Optional[str], list_type: str, data: Any) -> dict:
        body = {"name": name, "type": list_type}
        if description is not None:
            body["description"] = description
        if data is not None:
            body["data"] = data
        return body

    @staticmethod
    def _compose_update_body(id: str, name: str, description: Optional[str], list_type: str, data: Any) -> dict:
        body = {"id": id, "name": name, "type": list_type}
        if description is not None:
            body["description"] = description
        if data is not None:
            body["data"] = data
        return body

    @staticmethod
    def _compose_delete_body(id: str) -> dict:
        return {"id": id}

    @staticmethod
    def _compose_import_body(lists: List[dict]) -> dict:
        return {"lists": lists}

    @staticmethod
    def _compose_ip_body(id: str, ips: List[str]) -> dict:
        return {"id": id, "ips": ips}

    @staticmethod
    def _compose_check_ip_body(id: str, ip: str) -> dict:
        return {"id": id, "ip": ip}

    @staticmethod
    def _compose_text_body(id: str, texts: List[str]) -> dict:
        return {"id": id, "texts": texts}

    @staticmethod
    def _compose_check_text_body(id: str, text: str) -> dict:
        return {"id": id, "text": text}

    @staticmethod
    def _compose_clear_body(id: str) -> dict:
        return {"id": id}
