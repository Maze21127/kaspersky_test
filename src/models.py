from dataclasses import dataclass


@dataclass
class CVE:
    cve_id: str
    link: str


@dataclass
class Vulnerability:
    kaspersky_id: str
    name: str
    cve_lists: list[CVE] = None

    def __repr__(self):
        return f"{self.kaspersky_id} | {self.name}"
