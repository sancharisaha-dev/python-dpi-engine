"""Run the DPI engine against a real Wireshark capture.

Usage:
    uv run python scripts/run_real_capture.py capture.pcapng python_filtered.pcap

This is intentionally separate from the synthetic demo (generate_demo_pcap.py +
dpi_engine.py's __main__ block). Rules here are chosen based on domains and
IPs actually observed in the capture, so the DROP outcome is guaranteed to be
meaningful rather than coincidental.
"""

from __future__ import annotations

import sys
from pathlib import Path

from dpi.dpi_engine import DPIEngine


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: uv run python scripts/run_real_capture.py <input.pcapng> <output.pcap>")
        raise SystemExit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    engine = DPIEngine(num_workers=4)

    # Rule 1: block a real domain observed in the capture (SNI + DNS both
    # confirmed it). Demonstrates domain-based DROP.
    engine.block_domain("*.grammarly.io")

    # Rule 2: block a specific, real, frequently-talking remote IP from the
    # capture. Demonstrates IP-based DROP independent of domain visibility
    # (covers packets in the same flow that carry no SNI/Host/DNS payload).
    engine.block_ip("52.1.92.193")

    report = engine.process_file(str(input_path), str(output_path))

    engine.print_report()

    print()
    print(f"Filtered PCAP written to: {output_path.resolve()}")


if __name__ == "__main__":
    main()