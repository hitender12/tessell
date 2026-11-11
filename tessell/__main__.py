"""Command line entry point: ``python -m tessell`` runs the demo."""

from .demo import run_demo


def main() -> int:
    run_demo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
