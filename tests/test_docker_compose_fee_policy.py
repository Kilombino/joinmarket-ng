from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import yaml
from jmcore.fee_quantization import QUANT_REL

COMPOSE_FILE = Path(__file__).resolve().parents[1] / "docker-compose.yml"
E2E_MAKER_SERVICES = ("maker1", "maker2", "maker3", "maker4", "maker5")


def test_e2e_makers_advertise_distinct_public_grid_fees() -> None:
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    fees: list[Decimal] = []

    for service_name in E2E_MAKER_SERVICES:
        environment = compose["services"][service_name]["environment"]
        values = dict(item.split("=", 1) for item in environment)
        fees.append(Decimal(values["MAKER__CJ_FEE_RELATIVE"]))

    assert len(set(fees)) == len(E2E_MAKER_SERVICES)
    assert all(fee in QUANT_REL for fee in fees)
