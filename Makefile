.PHONY: install dev seed test cov lint type security audit check openapi

PORT ?= 8000

install:
	uv sync

dev:
	AUTHKIT_ENV=dev uv run uvicorn authkit.app:create_app --factory --reload --port $(PORT)

seed:
	AUTHKIT_ENV=dev uv run authkit seed-demo

test:
	uv run pytest

cov:
	uv run pytest --cov --cov-report=term-missing --cov-fail-under=90

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy

security:
	uv run bandit -q -r src -c pyproject.toml

audit:
	uv run pip-audit

openapi:
	uv run python scripts/export_openapi.py docs/openapi.json

check: lint type cov security
