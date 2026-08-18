.PHONY: test demo lint

test:
	PYTHONPATH=src python -m pytest -q

demo:
	PYTHONPATH=src python -m taintgate.cli demo

lint:
	python -m ruff check .
