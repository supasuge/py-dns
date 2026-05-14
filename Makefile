.PHONY: help sync install uninstall test lint check serve resolve inspect inspect-light web clean

DOMAIN ?= example.com
HOST ?= 127.0.0.1
PORT ?= 8080
DNS_PORT ?= 5353

help:
	@printf '%s\n' 'Targets:'
	@printf '%s\n' '  sync          Install project dependencies with uv'
	@printf '%s\n' '  install       Install py-dns globally with uv tool install .'
	@printf '%s\n' '  uninstall     Uninstall the py-dns uv tool'
	@printf '%s\n' '  test          Run pytest'
	@printf '%s\n' '  lint          Run ruff'
	@printf '%s\n' '  check         Run lint, tests, and web JS syntax check'
	@printf '%s\n' '  serve         Start the local DNS resolver'
	@printf '%s\n' '  resolve       Resolve DOMAIN through the secure chain'
	@printf '%s\n' '  inspect       Run the default aggressive inspection for DOMAIN'
	@printf '%s\n' '  inspect-light Run inspection without active/OSINT/bruteforce checks'
	@printf '%s\n' '  web           Serve docs/ locally for the web interface'
	@printf '%s\n' 'Variables: DOMAIN=example.com HOST=127.0.0.1 PORT=8080 DNS_PORT=5353'

sync:
	uv sync --extra dev

install:
	uv tool install .

uninstall:
	uv tool uninstall py-dns

test:
	uv run pytest

lint:
	uv run ruff check

check: lint test
	node --check docs/app.js

serve:
	uv run py-dns serve --host $(HOST) --port $(DNS_PORT)

resolve:
	uv run py-dns resolve $(DOMAIN)

inspect:
	uv run py-dns inspect $(DOMAIN)

inspect-light:
	uv run py-dns inspect $(DOMAIN) --no-active --no-osint --no-http --no-bruteforce-subdomains

web:
	python -m http.server $(PORT) --bind $(HOST) --directory docs

clean:
	find . -type d \( -name .pytest_cache -o -name .ruff_cache -o -name __pycache__ \) -prune -exec rm -rf {} +
