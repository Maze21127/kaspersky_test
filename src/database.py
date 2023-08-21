from sqlite3 import IntegrityError

import aiosqlite
from aiosqlite import Connection

from exceptions import AlreadyExists
from models import Vulnerability, CVE


class Database:
    def __init__(self, db_name: str):
        self.db_name = db_name

    @staticmethod
    async def _update_data(connection: Connection, query: str, args: tuple = tuple()):
        if args:
            await connection.execute(query, args)
        else:
            await connection.execute(query)

    async def create_tables(self):
        async with aiosqlite.connect(self.db_name) as db:
            try:
                await self._create_vulnerability_table(db)
                await self._create_cve_table(db)
                await self._create_vulnerability_to_cve_table(db)
                await db.commit()
            except Exception:
                await db.rollback()

    @staticmethod
    async def _create_vulnerability_table(db: Connection):
        await db.execute(
            """CREATE TABLE IF NOT EXISTS vulnerability (
            id VARCHAR(25) PRIMARY KEY,
            name TEXT NOT NULL)""")

    @staticmethod
    async def _create_cve_table(db: Connection):
        await db.execute(
            """CREATE TABLE IF NOT EXISTS cve (
            id VARCHAR(25) PRIMARY KEY,
            link TEXT)""")

    @staticmethod
    async def _create_vulnerability_to_cve_table(db: Connection):
        await db.execute(
            """CREATE TABLE IF NOT EXISTS vulnerability_cve (
            vulnerability_id INTEGER,
            cve_id VARCHAR(25),
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(id),
            FOREIGN KEY (cve_id) REFERENCES cve(id),
            PRIMARY KEY (vulnerability_id, cve_id))""")

    async def _insert_cve(self, connection: Connection, cve: CVE):
        query = "INSERT INTO cve (id, link) VALUES (?, ?)"
        await self._update_data(connection, query, (cve.cve_id, cve.link))
        return cve.cve_id

    async def _insert_vulnerability_to_cve(self, connection: Connection, cve_id: str, vulnerability_id: str):
        query = "INSERT INTO vulnerability_cve (vulnerability_id, cve_id) VALUES (?, ?)"
        return await self._update_data(connection, query, (vulnerability_id, cve_id))

    async def _insert_vulnerability(self, connection: Connection, vulnerability: Vulnerability):
        query = "INSERT INTO vulnerability (id, name) VALUES (?, ?)"
        await self._update_data(connection, query, (vulnerability.kaspersky_id, vulnerability.name,))
        for cve in vulnerability.cve_lists:
            cve_id = await self._insert_cve(connection, cve)
            await self._insert_vulnerability_to_cve(connection, cve_id, vulnerability.kaspersky_id)

    async def insert_vulnerability(self, vulnerability: Vulnerability):
        async with aiosqlite.connect(self.db_name) as db:
            try:
                await self._insert_vulnerability(db, vulnerability)
                await db.commit()
            except IntegrityError:
                await db.rollback()
                raise AlreadyExists()
