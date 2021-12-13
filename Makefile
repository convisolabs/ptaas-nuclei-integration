PYTHON = python3
RM = rm
PROGRAM_NAME = ptaas-nuclei-integration

PRJ_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VENV ?= $(PRJ_DIR)venv

install: $(VENV) setup.py
	$(VENV)/bin/pip install -U .

$(VENV):
	$(PYTHON) -m venv $(VENV)

uninstall: $(VENV)
	$(VENV)/bin/pip uninstall -y $(PROGRAM_NAME)

clean:
	$(RM) -rf $(VENV)
