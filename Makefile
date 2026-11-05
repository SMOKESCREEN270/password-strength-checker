.PHONY: install test lint typecheck coverage build demo clean

install:
	python -m pip install -e ".[dev]"

test:
	python -m unittest discover -s tests -v

lint:
	ruff check src tests

typecheck:
	mypy

coverage:
	coverage run -m unittest discover -s tests
	coverage report

build:
	python -m build

demo:
	sh scripts/demo.sh

clean:
	rm -rf build dist .mypy_cache .ruff_cache .coverage htmlcov src/*.egg-info
