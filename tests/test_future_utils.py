import asyncio
import unittest

from descope.future_utils import resolve, then, wrap


class TestFutureUtils(unittest.TestCase):
    def test_then_with_sync_result(self):
        result = then("test_result", lambda x: f"modified_{x}")
        self.assertEqual(result, "modified_test_result")

    def test_then_with_coroutine(self):
        async def async_func():
            return "async_result"

        result = then(async_func(), lambda x: f"modified_{x}")
        self.assertTrue(asyncio.iscoroutine(result))

        async def run_test():
            actual_result = await result
            self.assertEqual(actual_result, "modified_async_result")

        asyncio.run(run_test())

    def test_then_with_future(self):
        async def run_test():
            future = asyncio.Future()
            future.set_result("future_result")

            result = then(future, lambda x: f"modified_{x}")
            self.assertTrue(asyncio.iscoroutine(result))

            actual_result = await result
            self.assertEqual(actual_result, "modified_future_result")

        asyncio.run(run_test())

    def test_wrap_with_false(self):
        wrapped = wrap("test_result", False)
        self.assertEqual(wrapped, "test_result")
        self.assertFalse(asyncio.iscoroutine(wrapped))

    def test_wrap_with_true(self):
        wrapped = wrap("test_result", True)
        self.assertTrue(asyncio.iscoroutine(wrapped))

        async def run_test():
            actual_result = await wrapped
            self.assertEqual(actual_result, "test_result")

        asyncio.run(run_test())

    def test_resolve_with_sync_object(self):
        async def run_test():
            result = await resolve("sync_object")
            self.assertEqual(result, "sync_object")

        asyncio.run(run_test())

    def test_resolve_with_coroutine(self):
        async def async_func():
            return "coroutine_result"

        async def run_test():
            result = await resolve(async_func())
            self.assertEqual(result, "coroutine_result")

        asyncio.run(run_test())

    def test_resolve_with_future(self):
        async def run_test():
            future = asyncio.Future()
            future.set_result("future_result")

            result = await resolve(future)
            self.assertEqual(result, "future_result")

        asyncio.run(run_test())

    def test_then_with_complex_modifier(self):
        result = then({"key": "value"}, lambda x: {**x, "modified": True})
        self.assertEqual(result, {"key": "value", "modified": True})

    def test_wrap_with_none(self):
        wrapped = wrap(None, True)
        self.assertTrue(asyncio.iscoroutine(wrapped))

        async def run_test():
            actual_result = await wrapped
            self.assertIsNone(actual_result)

        asyncio.run(run_test())

    def test_resolve_with_none(self):
        async def run_test():
            result = await resolve(None)
            self.assertIsNone(result)

        asyncio.run(run_test())

    def test_then_with_exception_in_modifier(self):
        def modifier(x):
            raise ValueError("Test exception")

        with self.assertRaises(ValueError):
            then("test_result", modifier)

    def test_then_with_exception_in_async_modifier(self):
        async def async_func():
            return "async_result"

        def modifier(x):
            raise ValueError("Test exception")

        result = then(async_func(), modifier)

        async def run_test():
            with self.assertRaises(ValueError):
                _ = await result

        asyncio.run(run_test())

    def test_resolve_with_exception_in_coroutine(self):
        async def async_func():
            raise ValueError("Test exception")

        async def run_test():
            with self.assertRaises(ValueError):
                await resolve(async_func())

        asyncio.run(run_test())

    def test_wrap_with_false_and_none(self):
        wrapped = wrap(None, False)
        self.assertIsNone(wrapped)
        self.assertFalse(asyncio.iscoroutine(wrapped))


if __name__ == "__main__":
    unittest.main()
