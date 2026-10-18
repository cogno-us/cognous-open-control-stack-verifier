# Contributor gates. Activate a virtualenv with `pip install -e ".[dev]"` first.
# Nothing here publishes anything.
PY ?= python

.PHONY: check lint type tests

check: lint type tests

lint:
	ruff check .
	ruff format --check .

type:
	mypy

# --disable-socket and the 80% coverage floor come from [tool.pytest.ini_options] addopts.
tests:
	$(PY) -m pytest -q
