from __future__ import annotations

from asyncio import Event, Lock
from contextlib import asynccontextmanager


class RWLock:
    def __init__(self):
        self.__reading = Event()
        self.__writing = Event()

        self.__readers = 0

        self.__readers_lock = Lock()

    @asynccontextmanager
    async def read(self):
        if self.__writing.is_set():
            await self.__writing.wait()

        async with self.__readers_lock:
            self.__readers += 1
            self.__reading.set()

        try:
            yield
        finally:
            async with self.__readers_lock:
                self.__readers -= 1
                if self.__readers == 0:
                    self.__reading.clear()

    @asynccontextmanager
    async def write(self):
        if self.__reading.is_set():
            await self.__reading.wait()

        if self.__writing.is_set():
            await self.__writing.wait()

        self.__writing.set()
        try:
            yield
        finally:
            self.__writing.clear()
