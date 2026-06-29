from __future__ import annotations

from typing import Any, List, Optional

from descope._http_base import HTTPBase
from descope.management._lists_base import ListsBase
from descope.management.common import MgmtV1


class Lists(ListsBase, HTTPBase):
    def create(
        self,
        name: str,
        list_type: str,
        description: Optional[str] = None,
        data: Any = None,
    ) -> dict:
        """
        Create a new list with the given name and type.

        Args:
        name (str): The list's name (required, must be unique).
        list_type (str): The list type - "texts", "ips", or "json" (required).
        description (str, optional): Optional list description.
        data (Any, optional): The list data - format depends on type:
            - For "texts" and "ips": list of strings
            - For "json": dict

        Return value (dict):
        Return dict in the format {"list": {...}}.

        Raise:
        AuthException: raised if create operation fails
        """
        response = self._http.post(
            MgmtV1.list_path,
            body=ListsBase._compose_create_body(name, description, list_type, data),
        )
        return response.json()

    def update(
        self,
        id: str,
        name: str,
        list_type: str,
        description: Optional[str] = None,
        data: Any = None,
    ) -> dict:
        """
        Update an existing list. All parameters are required and will override
        whatever value is currently set in the existing list. Use carefully.

        Args:
        id (str): The ID of the list to update.
        name (str): Updated list name.
        list_type (str): The list type - "texts", "ips", or "json".
        description (str, optional): Updated description.
        data (Any, optional): Updated list data.

        Return value (dict):
        Return dict in the format {"list": {...}}.

        Raise:
        AuthException: raised if update operation fails
        """
        response = self._http.post(
            MgmtV1.list_update_path,
            body=ListsBase._compose_update_body(id, name, description, list_type, data),
        )
        return response.json()

    def delete(self, id: str):
        """
        Delete an existing list. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The ID of the list to delete.

        Raise:
        AuthException: raised if deletion operation fails
        """
        self._http.post(MgmtV1.list_delete_path, body=ListsBase._compose_delete_body(id))

    def load(self, id: str) -> dict:
        """
        Load a list by ID.

        Args:
        id (str): The ID of the list to load.

        Return value (dict):
        Return dict in the format {"list": {...}}.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(MgmtV1.list_path, params={"id": id})
        return response.json()

    def load_by_name(self, name: str) -> dict:
        """
        Load a list by name.

        Args:
        name (str): The name of the list to load.

        Return value (dict):
        Return dict in the format {"list": {...}}.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(MgmtV1.list_name_path, params={"name": name})
        return response.json()

    def load_all(self) -> dict:
        """
        Load all lists in the project.

        Return value (dict):
        Return dict in the format {"lists": [{...}, ...]}.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(MgmtV1.list_all_path)
        return response.json()

    def import_lists(self, lists: List[dict]):
        """
        Import multiple lists into the project. This will create or update
        lists based on their ID.

        Args:
        lists (List[dict]): List of list objects to import.

        Raise:
        AuthException: raised if import operation fails
        """
        self._http.post(MgmtV1.list_import_path, body=ListsBase._compose_import_body(lists))

    def add_ips(self, id: str, ips: List[str]):
        """
        Add IP addresses to an IP list. The list must be of type "ips".
        Duplicate IPs are automatically ignored. The order of existing IPs is
        preserved and new IPs are appended.

        Args:
        id (str): The ID of the IP list.
        ips (List[str]): List of IP addresses to add.

        Raise:
        AuthException: raised if operation fails
        """
        self._http.post(MgmtV1.list_ip_add_path, body=ListsBase._compose_ip_body(id, ips))

    def remove_ips(self, id: str, ips: List[str]):
        """
        Remove IP addresses from an IP list. The list must be of type "ips".
        Non-existent IPs are silently ignored.

        Args:
        id (str): The ID of the IP list.
        ips (List[str]): List of IP addresses to remove.

        Raise:
        AuthException: raised if operation fails
        """
        self._http.post(MgmtV1.list_ip_remove_path, body=ListsBase._compose_ip_body(id, ips))

    def check_ip(self, id: str, ip: str) -> bool:
        """
        Check if an IP address exists in an IP list. The list must be of type "ips".

        Args:
        id (str): The ID of the IP list.
        ip (str): The IP address to check.

        Return value (bool):
        True if the IP exists in the list, False otherwise.

        Raise:
        AuthException: raised if operation fails
        """
        response = self._http.post(MgmtV1.list_ip_check_path, body=ListsBase._compose_check_ip_body(id, ip))
        result = response.json()
        return result.get("exists", False)

    def add_texts(self, id: str, texts: List[str]):
        """
        Add text items to a text list. The list must be of type "texts".
        Duplicate texts are automatically ignored. The order of existing texts is
        preserved and new texts are appended.

        Args:
        id (str): The ID of the text list.
        texts (List[str]): List of text items to add.

        Raise:
        AuthException: raised if operation fails
        """
        self._http.post(MgmtV1.list_text_add_path, body=ListsBase._compose_text_body(id, texts))

    def remove_texts(self, id: str, texts: List[str]):
        """
        Remove text items from a text list. The list must be of type "texts".
        Non-existent texts are silently ignored.

        Args:
        id (str): The ID of the text list.
        texts (List[str]): List of text items to remove.

        Raise:
        AuthException: raised if operation fails
        """
        self._http.post(MgmtV1.list_text_remove_path, body=ListsBase._compose_text_body(id, texts))

    def check_text(self, id: str, text: str) -> bool:
        """
        Check if a text exists in a text list. The list must be of type "texts".

        Args:
        id (str): The ID of the text list.
        text (str): The text to check.

        Return value (bool):
        True if the text exists in the list, False otherwise.

        Raise:
        AuthException: raised if operation fails
        """
        response = self._http.post(MgmtV1.list_text_check_path, body=ListsBase._compose_check_text_body(id, text))
        result = response.json()
        return result.get("exists", False)

    def clear(self, id: str):
        """
        Clear all data from a list. The list metadata (name, description, type) is
        preserved. For "json" type lists, sets data to empty object. For "texts" and
        "ips" type lists, sets data to empty array.

        Args:
        id (str): The ID of the list to clear.

        Raise:
        AuthException: raised if operation fails
        """
        self._http.post(MgmtV1.list_clear_path, body=ListsBase._compose_clear_body(id))
