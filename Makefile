.PHONY: setup demo test lint clean

PY ?= python3
VENV := .venv
VPY := $(VENV)/bin/python
PYTHONPATH := src

setup:
	$(PY) -m venv $(VENV)
	$(VPY) -c "import sys; print('python', sys.version)"

demo: setup
	PYTHONPATH=$(PYTHONPATH) $(VPY) -m portfolio_proof report --examples examples --artifacts artifacts
	@echo
	@echo "Generated: artifacts/report.md"
	@echo "Preview:"
	@sed -n '1,140p' artifacts/report.md

lint: setup
	$(VPY) -m compileall src tests
	PYTHONPATH=$(PYTHONPATH) $(VPY) -m portfolio_proof validate --examples examples

test: setup
	PYTHONPATH=$(PYTHONPATH) $(VPY) -m unittest discover -s tests -v

clean:
	rm -rf artifacts $(VENV)
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
