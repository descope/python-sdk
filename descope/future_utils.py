from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, TypeVar, Union

T = TypeVar("T")


def futu_apply(
    result_or_coro: Union[T, Awaitable[T]], modifier: Callable[[T], Any]
) -> Union[Any, Awaitable[Any]]:
    if asyncio.iscoroutine(result_or_coro):

        async def process_async():
            result = await result_or_coro
            return modifier(result)

        return process_async()
    else:
        return modifier(result_or_coro)


def futu_awaitable(result: T, as_awaitable: bool) -> Union[Any, Awaitable[Any]]:
    if as_awaitable:

        async def awaitable_wrapper():
            return result

        return awaitable_wrapper()

    return result


async def futu_await(obj: Union[Any, Awaitable[Any]]) -> Any:
    if asyncio.iscoroutine(obj) or asyncio.isfuture(obj):
        return await obj
    return obj
