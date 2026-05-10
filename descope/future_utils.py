from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, TypeVar, Union

T = TypeVar("T")


def then(result_or_coro: Union[T, Awaitable[T]], modifier: Callable[[T], Any]) -> Union[Any, Awaitable[Any]]:
    if inspect.isawaitable(result_or_coro):

        async def process_async():
            result = await result_or_coro
            return modifier(result)

        return process_async()

    return modifier(result_or_coro)  # type: ignore[arg-type]


def wrap(result: T, as_awaitable: bool) -> Union[Any, Awaitable[Any]]:
    if as_awaitable:

        async def awaitable_wrapper():
            return result

        return awaitable_wrapper()

    return result


async def resolve(obj: Union[Any, Awaitable[Any]]) -> Any:
    if inspect.isawaitable(obj):
        return await obj
    return obj
