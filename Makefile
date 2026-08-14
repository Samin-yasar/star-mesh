.PHONY: help all paper python-poc rust-poc clean

PYTHON ?= python3
VENV_DIR := .venv
VENV_PYTHON := $(VENV_DIR)/bin/python3

help:
	@echo "Star-Mesh research repository"
	@echo ""
	@echo "Targets:"
	@echo "  make paper        Build the LaTeX manuscript"
	@echo "  make python-poc   Run the Python protocol demonstration"
	@echo "  make rust-poc     Run the Rust proof-of-concept"
	@echo "  make clean        Remove paper build artifacts"
	@echo "  make help         Show this message"

all: paper

paper:
	$(MAKE) -C paper all

$(VENV_PYTHON):
	$(PYTHON) -m venv $(VENV_DIR)

python-poc: $(VENV_PYTHON)
	$(VENV_PYTHON) poc/python/poc.py

rust-poc:
	cargo run --manifest-path poc/rust/Cargo.toml

clean:
	$(MAKE) -C paper clean
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
