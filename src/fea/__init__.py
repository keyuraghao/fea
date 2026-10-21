"""FEA - Forensic Evidence Agent: one MCP (and CLI) for disk-image forensics."""
__version__ = "0.1.0"


def main() -> None:
    from .cli import main as _main
    _main()
