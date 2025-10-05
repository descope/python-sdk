import asyncio
import unittest
from unittest.mock import Mock, patch

from descope.future_utils import futu_apply, futu_await, futu_awaitable


class TestFutureUtils(unittest.TestCase):
    def test_futu_apply_with_sync_result(self):
        """Test futu_apply with synchronous result"""
        result = "test_result"
        modifier = lambda x: f"modified_{x}"

        result = futu_apply(result, modifier)
        self.assertEqual(result, "modified_test_result")

    def test_futu_apply_with_coroutine(self):
        """Test futu_apply with coroutine"""

        async def async_func():
            return "async_result"

        modifier = lambda x: f"modified_{x}"

        result = futu_apply(async_func(), modifier)
        self.assertTrue(asyncio.iscoroutine(result))

        # Test the actual result
        async def run_test():
            actual_result = await result
            self.assertEqual(actual_result, "modified_async_result")

        asyncio.run(run_test())

    def test_futu_apply_with_future(self):
        """Test futu_apply with future"""

        async def run_test():
            future = asyncio.Future()
            future.set_result("future_result")

            modifier = lambda x: f"modified_{x}"

            result = futu_apply(future, modifier)
            self.assertTrue(asyncio.iscoroutine(result))

            # Test the actual result
            actual_result = await result
            self.assertEqual(actual_result, "modified_future_result")

        asyncio.run(run_test())

    def test_futu_awaitable_with_false(self):
        """Test futu_awaitable with as_awaitable=False"""
        result = "test_result"
        awaitable_result = futu_awaitable(result, False)

        self.assertEqual(awaitable_result, "test_result")
        self.assertFalse(asyncio.iscoroutine(awaitable_result))

    def test_futu_awaitable_with_true(self):
        """Test futu_awaitable with as_awaitable=True"""
        result = "test_result"
        awaitable_result = futu_awaitable(result, True)

        self.assertTrue(asyncio.iscoroutine(awaitable_result))

        # Test the actual result
        async def run_test():
            actual_result = await awaitable_result
            self.assertEqual(actual_result, "test_result")

        asyncio.run(run_test())

    def test_futu_await_with_sync_object(self):
        """Test futu_await with synchronous object"""
        obj = "sync_object"

        async def run_test():
            result = await futu_await(obj)
            self.assertEqual(result, "sync_object")

        asyncio.run(run_test())

    def test_futu_await_with_coroutine(self):
        """Test futu_await with coroutine"""

        async def async_func():
            return "coroutine_result"

        async def run_test():
            result = await futu_await(async_func())
            self.assertEqual(result, "coroutine_result")

        asyncio.run(run_test())

    def test_futu_await_with_future(self):
        """Test futu_await with future"""

        async def run_test():
            future = asyncio.Future()
            future.set_result("future_result")

            result = await futu_await(future)
            self.assertEqual(result, "future_result")

        asyncio.run(run_test())

    def test_futu_apply_with_complex_modifier(self):
        """Test futu_apply with complex modifier function"""
        result = {"key": "value"}
        modifier = lambda x: {**x, "modified": True}

        result = futu_apply(result, modifier)
        expected = {"key": "value", "modified": True}
        self.assertEqual(result, expected)

    def test_futu_apply_with_async_modifier(self):
        """Test futu_apply with async modifier"""

        async def async_func():
            return "async_result"

        def modifier(x):
            return f"modified_{x}"

        result = futu_apply(async_func(), modifier)

        async def run_test():
            actual_result = await result
            self.assertEqual(actual_result, "modified_async_result")

        asyncio.run(run_test())

    def test_futu_awaitable_with_none_result(self):
        """Test futu_awaitable with None result"""
        result = None
        awaitable_result = futu_awaitable(result, True)

        self.assertTrue(asyncio.iscoroutine(awaitable_result))

        async def run_test():
            actual_result = await awaitable_result
            self.assertIsNone(actual_result)

        asyncio.run(run_test())

    def test_futu_await_with_none_object(self):
        """Test futu_await with None object"""

        async def run_test():
            result = await futu_await(None)
            self.assertIsNone(result)

        asyncio.run(run_test())

    def test_futu_apply_with_exception_in_modifier(self):
        """Test futu_apply when modifier raises exception"""
        result = "test_result"

        def modifier(x):
            raise ValueError("Test exception")

        with self.assertRaises(ValueError):
            futu_apply(result, modifier)

    def test_futu_apply_with_exception_in_async_modifier(self):
        """Test futu_apply when async modifier raises exception"""

        async def async_func():
            return "async_result"

        def modifier(x):
            raise ValueError("Test exception")

        result = futu_apply(async_func(), modifier)

        async def run_test():
            with self.assertRaises(ValueError):
                await result

        asyncio.run(run_test())

    def test_futu_await_with_exception_in_coroutine(self):
        """Test futu_await when coroutine raises exception"""

        async def async_func():
            raise ValueError("Test exception")

        async def run_test():
            with self.assertRaises(ValueError):
                await futu_await(async_func())

        asyncio.run(run_test())

    def test_futu_awaitable_with_false_and_none(self):
        """Test futu_awaitable with as_awaitable=False and None result"""
        result = None
        awaitable_result = futu_awaitable(result, False)

        self.assertIsNone(awaitable_result)
        self.assertFalse(asyncio.iscoroutine(awaitable_result))


if __name__ == "__main__":
    unittest.main()
