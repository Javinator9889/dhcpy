from __future__ import annotations

import os
import csv
import shutil
from contextlib import asynccontextmanager
from io import StringIO
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING

from .host import Host, Item, Pattern
from .lock import RWLock

if TYPE_CHECKING:
    from logging import Logger
    from typing import AsyncIterator, Optional, TypeVar, TextIO
    from typing_extensions import Protocol

    T = TypeVar("T")

    class Database(Protocol[T]):
        def all(self) -> AsyncIterator[T]:
            ...

        def get(self, pattern: Pattern = Pattern()) -> AsyncIterator[T]:
            ...

        async def delete(self, item: Optional[T] = None, /, pattern: Pattern = Pattern()) -> None:
            ...

        async def add(self, row: T) -> None:
            ...


class CSVDatabase:
    def __init__(self, file: Path, log: Logger = getLogger(__name__)):
        self.log = log
        self.log.debug("initializing CSV database for file %s", file)
        self.file = file
        if not self.file.is_file():
            self.file.touch()
        self.lock = RWLock()

    @asynccontextmanager
    async def reader(self, fd: Optional[TextIO] = None, do_close: bool = True) -> AsyncIterator[csv.DictReader[str]]:
        fd = fd or open(self.file, encoding="utf-8", newline="")
        try:
            async with self.lock.read():
                yield csv.DictReader(fd, fieldnames=tuple(Item.__fields__))
        finally:
            if do_close:
                fd.close()

    @asynccontextmanager
    async def writer(self, fd: Optional[TextIO] = None, do_close: bool = True) -> AsyncIterator[csv.DictWriter[str]]:
        fd = fd or open(self.file, mode="a", encoding="utf-8", newline="")
        try:
            async with self.lock.write():
                yield csv.DictWriter(fd, fieldnames=tuple(Item.__fields__))
        finally:
            if do_close:
                fd.close()

    async def all(self) -> AsyncIterator[Item]:
        self.log.debug("reading all data from CSV file")
        async with self.reader() as reader:
            for row in reader:
                yield Item.parse_obj(row)

    async def get(self, pattern: Pattern = Pattern()) -> AsyncIterator[Item]:
        self.log.debug("matching pattern from CSV file: %s", pattern)
        async for line in self.all():
            if pattern == line.to_tuple():
                yield line

    async def delete(self, item: Optional[Item] = None, /, pattern: Pattern = Pattern()):
        if item is not None:
            self.log.debug("deleting item %s from CSV file", item)

        if pattern is not Pattern():
            self.log.debug("removing pattern %s from CSV file", pattern)
        tmp = StringIO()
        lines_to_delete = {line async for line in self.get(pattern)}
        self.log.debug("removing lines %s from db", lines_to_delete)
        if item is not None:
            lines_to_delete.add(item)
        lines = {line async for line in self.all()}
        lines -= lines_to_delete

        async with self.writer(tmp, do_close=False) as writer:
            writer.writerows(line.dict() for line in lines)
            tmp.seek(os.SEEK_SET)
            with open(self.file, "w", encoding="utf-8") as dest:
                shutil.copyfileobj(tmp, dest)


    async def add(self, row: Item):
        self.log.debug("adding item %s", row)
        async with self.writer() as writer:
            writer.writerow(row.dict())


class HostDatabase:
    def __init__(self, database: Database[Item], log: Logger = getLogger(__name__)):
        self.log = log
        self.log.debug("initializing host db with container db: %s", database)
        self.db = database

    async def get(self, pattern: Pattern = Pattern()) -> AsyncIterator[Host]:
        async for data in self.db.get(pattern):
            yield Host(**data.dict())

    async def add(self, host: Host):
        await self.db.add(Item.parse_obj(host.to_tuple()))

    async def delete(self, host: Optional[Host] = None, /, pattern: Pattern = Pattern()):
        pattern = host.to_pattern() if host is not None else pattern
        await self.db.delete(pattern=pattern)

    async def all(self) -> AsyncIterator[Host]:
        async for data in self.db.all():
            yield Host.from_tuple(data)

    async def replace(self, host: Host):
        await self.delete(host)
        await self.add(host)
