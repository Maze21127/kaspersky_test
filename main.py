import argparse
import asyncio

from bs4 import BeautifulSoup
import aiohttp

from src.database import Database
from src.exceptions import ProductNotFound, AlreadyExists
from src.models import CVE, Vulnerability

BASE_URL = "https://threats.kaspersky.com/en/"
THREATS_URL = f"{BASE_URL}/product/"
VULNERABILITY_URL = f"{BASE_URL}/vulnerability/"


def get_cve_list_from_page(raw_html: str):
    soup = BeautifulSoup(raw_html, features='html.parser')
    cve_links = soup.find_all('a', class_='gtm_vulnerabilities_cve')
    return [(CVE(cve_id=link.get_text(), link=link['href'])) for link in cve_links]


async def fetch_cve_list_for_vulnerability(vulnerability: Vulnerability, session: aiohttp.ClientSession):
    async with session.get(f"{VULNERABILITY_URL}/{vulnerability.kaspersky_id}") as response:
        raw_html = await response.text()
        cve_lists = get_cve_list_from_page(raw_html)
        vulnerability.cve_lists = cve_lists
        return vulnerability


async def fetch_vulnerabilities(name: str) -> list[Vulnerability]:
    async with aiohttp.ClientSession() as session:
        async with session.get(f'{THREATS_URL}/{name}') as response:
            if response.status == 404:
                raise ProductNotFound()
            raw_html = await response.text()
            vulnerabilities = get_vulnerabilities(raw_html)
            tasks = [asyncio.create_task(fetch_cve_list_for_vulnerability(i, session)) for i in vulnerabilities]
            result = await asyncio.gather(*tasks)
    return result


def get_vulnerabilities(raw_html: str) -> list[Vulnerability]:
    soup = BeautifulSoup(raw_html, features='html.parser')
    result = []
    for row in soup.find_all(class_='line_info line_info_vendor line_list2'):
        id_element = row.find('a', href=True)
        name_element = row.find_all('a', href=True)[1]
        kaspersky_id = id_element.get_text(strip=True)
        name = name_element.get_text(strip=True)
        result.append(
            Vulnerability(
                kaspersky_id=kaspersky_id,
                name=name
            )
        )
    return result


async def main(product_name: str):
    db = Database('database.db')
    await db.create_tables()
    try:
        vulnerabilities = await fetch_vulnerabilities(product_name)
    except ProductNotFound:
        return print(f'Product "{product_name}" not found')
    for vulnerability in vulnerabilities:
        try:
            await db.insert_vulnerability(vulnerability=vulnerability)
        except AlreadyExists:
            return print(f'Vulnerability "{vulnerability}" already exists')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Process product name for vulnerability fetch.")
    parser.add_argument("-p", "--product_name", type=str, required=True,
                        help="Name of the product to fetch vulnerabilities for.")
    args = parser.parse_args()

    asyncio.run(main(args.product_name))
