SHELL := /bin/bash

PY_SDK_VENV := sdk/python/.venv
PY_SDK_PYTHON := $(PY_SDK_VENV)/bin/python

.PHONY: up up-dev down migrate test smoke logs fmt sdk-test sdk-conformance wait-ready sdk-python-venv

up:
	docker compose -f docker-compose.dev.yml up --build -d
	$(MAKE) migrate
	$(MAKE) wait-ready

up-dev: up

wait-ready:
	@for i in {1..180}; do \
		if curl -sf http://localhost:8080/health >/dev/null && \
		   curl -sf http://localhost:8081/health >/dev/null && \
		   curl -sf http://localhost:8082/health >/dev/null && \
		   curl -sf http://localhost:8083/health >/dev/null; then \
			echo "services ready"; \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "services not ready"; \
	exit 1

down:
	docker compose -f docker-compose.dev.yml down -v

migrate:
	docker compose -f docker-compose.dev.yml run --rm migrate

test:
	go test ./... -count=1

smoke:
	bash scripts/smoke.sh

sdk-python-venv:
	test -x $(PY_SDK_PYTHON) || python3 -m venv $(PY_SDK_VENV)
	PYTHONNOUSERSITE=1 $(PY_SDK_PYTHON) -m pip install -U pip setuptools wheel >/dev/null
	PYTHONNOUSERSITE=1 $(PY_SDK_PYTHON) -m pip install -e "sdk/python[dev]" >/dev/null

sdk-test: wait-ready
	go test ./sdk/go/contractlane -count=1
	test -f sdk/typescript/package-lock.json || (echo "sdk/typescript/package-lock.json is required for npm ci"; exit 1)
	cd sdk/typescript && npm ci && npm run build && CL_INTEGRATION=1 CL_BASE_URL=http://localhost:8080 CL_IAL_BASE_URL=http://localhost:8081 npm test
	$(MAKE) sdk-python-venv
	PYTHONNOUSERSITE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 CL_INTEGRATION=1 CL_BASE_URL=http://localhost:8080 CL_IAL_BASE_URL=http://localhost:8081 $(PY_SDK_PYTHON) -m pytest sdk/python/tests -q
	CL_INTEGRATION=1 CL_BASE_URL=http://localhost:8080 CL_IAL_BASE_URL=http://localhost:8081 go test ./sdk/go/contractlane -count=1

sdk-conformance: wait-ready
	bash conformance/runner/run_local_conformance.sh

logs:
	docker compose -f docker-compose.dev.yml logs -f --tail=200

fmt:
	gofmt -w .
