"""Dependency-free controller health probe used by the container image."""

from urllib.request import urlopen


def main() -> int:
    try:
        with urlopen("http://127.0.0.1:8000/api/v1/health", timeout=3) as response:
            return 0 if 200 <= response.status < 400 else 1
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
