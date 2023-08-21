from sqlite3 import IntegrityError

import aiosqlite
from aiosqlite import Connection, Cursor


from src.models import Vulnerability, CVE


class Database:
    def __init__(self, db_name: str):
        self.db_name = db_name

    @staticmethod
    async def _execute_query(connection: Connection, query: str, args: tuple = tuple()):
        if args:
            return await connection.execute(query, args)
        else:
            return await connection.execute(query)

    async def create_tables(self):
        async with aiosqlite.connect(self.db_name) as db:
            try:
                await self._create_product_table(db)
                await self._create_vulnerability_table(db)
                await self._create_cve_table(db)
                await self._create_vulnerability_to_cve_table(db)
                await self._create_product_vulnerability_table(db)
                await db.commit()
            except Exception:
                await db.rollback()

    @staticmethod
    async def _create_product_table(db: Connection):
        await db.execute(
            """CREATE TABLE IF NOT EXISTS product (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL)""")

    @staticmethod
    async def _create_vulnerability_table(db: Connection):
        await db.execute(
            """CREATE TABLE IF NOT EXISTS vulnerability (
            id VARCHAR(25) PRIMARY KEY,
            name TEXT NOT NULL)""")

    @staticmethod
    async def _create_product_vulnerability_table(db: Connection):
        await db.execute(
            """CREATE TABLE IF NOT EXISTS product_vulnerability (
            product_id INTEGER,
            vulnerability_id VARCHAR(25),
            FOREIGN KEY (product_id) REFERENCES product(id),
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(id),
            PRIMARY KEY (product_id, vulnerability_id))""")

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

    async def _insert_or_get_cve(self, connection: Connection, cve: CVE):
        query = "INSERT INTO cve (id, link) VALUES (?, ?)"
        try:
            await self._execute_query(connection, query, (cve.cve_id, cve.link))
        except IntegrityError:
            return cve.cve_id
        return cve.cve_id

    async def _insert_vulnerability_to_cve(self, connection: Connection, cve_id: str, vulnerability_id: str):
        query = "INSERT INTO vulnerability_cve (vulnerability_id, cve_id) VALUES (?, ?)"
        return await self._execute_query(connection, query, (vulnerability_id, cve_id))

    async def _insert_product(self, connection: Connection, product_name: str):
        query = "INSERT INTO product (name) VALUES (?)"
        cursor = await self._execute_query(connection, query, (product_name,))
        return cursor.lastrowid

    async def is_product_exists(self, product_name: str):
        async with aiosqlite.connect(self.db_name) as connection:
            query = "SELECT id FROM product WHERE name = ?"
            query_result: Cursor = await self._execute_query(connection, query, (product_name,))
            return bool(await query_result.fetchone())

    async def _insert_or_get_product(self, connection: Connection, product_name: str):
        query = "SELECT id FROM product WHERE name = ?"
        query_result: Cursor = await self._execute_query(connection, query, (product_name,))
        data = await query_result.fetchone()
        if data:
            return data[0]
        else:
            return await self._insert_product(connection, product_name)

    async def _insert_product_vulnerability(self, connection: Connection, product_id: int, vulnerability_id: str):
        query = "INSERT INTO product_vulnerability (product_id, vulnerability_id) VALUES (?, ?)"
        return await self._execute_query(connection, query, (product_id, vulnerability_id))

    async def _insert_vulnerability(self, connection: Connection, vulnerability: Vulnerability, product_name: str):
        query = "INSERT INTO vulnerability (id, name) VALUES (?, ?)"
        await self._execute_query(connection, query, (vulnerability.kaspersky_id, vulnerability.name,))
        product_id = await self._insert_or_get_product(connection, product_name)
        await self._insert_product_vulnerability(connection, product_id, vulnerability.kaspersky_id)
        for cve in vulnerability.cve_lists:
            cve_id = await self._insert_or_get_cve(connection, cve)
            await self._insert_vulnerability_to_cve(connection, cve_id, vulnerability.kaspersky_id)

    async def insert_vulnerability(self, vulnerability: Vulnerability, product_name: str):
        async with aiosqlite.connect(self.db_name) as db:
            try:
                await self._insert_vulnerability(db, vulnerability, product_name)
                await db.commit()
            except IntegrityError:
                await db.rollback()
