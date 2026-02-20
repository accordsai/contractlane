SHELL := /bin/bash

PY_SDK_VENV := sdk/python/.venv
PY_SDK_PYTHON := $(PY_SDK_VENV)/bin/python

.PHONY: up up-dev up-prod down down-prod migrate migrate-prod test smoke logs logs-prod fmt sdk-test sdk-conformance wait-ready wait-ready-prod sdk-python-venv test-sdk-python sdk-sanity

up:
	docker compose -f docker-compose.dev.yml up --build -d
        sleep 2
	$(MAKE) migrate
	$(MAKE) wait-ready

up-dev: up

up-prod:
	bash scripts/prod_preflight.sh
	docker compose -f docker-compose.prod.yml up --build -d postgres
	$(MAKE) migrate-prod
	docker compose -f docker-compose.prod.yml up --build -d ial execution cel
	$(MAKE) wait-ready-prod

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

wait-ready-prod:
	@for i in {1..180}; do \
		if curl -sf http://localhost:8081/health >/dev/null && \
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

down-prod:
	docker compose -f docker-compose.prod.yml down

migrate:
	docker compose -f docker-compose.dev.yml run --rm migrate

migrate-prod:
	docker compose -f docker-compose.prod.yml run --rm migrate

test:
	go test ./... -count=1

smoke:
	bash scripts/smoke.sh

sdk-python-venv:
	test -x $(PY_SDK_PYTHON) || python3 -m venv $(PY_SDK_VENV)
	PYTHONNOUSERSITE=1 $(PY_SDK_PYTHON) -m pip install -U pip setuptools wheel >/dev/null
	PYTHONNOUSERSITE=1 $(PY_SDK_PYTHON) -m pip install -e "sdk/python[dev]" >/dev/null

test-sdk-python: sdk-python-venv
	PYTHONNOUSERSITE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 $(PY_SDK_PYTHON) -m pytest sdk/python/tests -q

sdk-test: wait-ready
	go test ./sdk/go/contractlane -count=1
	test -f sdk/typescript/package-lock.json || (echo "sdk/typescript/package-lock.json is required for npm ci"; exit 1)
	cd sdk/typescript && npm ci && npm run build && CL_INTEGRATION=1 CL_BASE_URL=http://localhost:8080 CL_IAL_BASE_URL=http://localhost:8081 npm test
	$(MAKE) sdk-python-venv
	PYTHONNOUSERSITE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 CL_INTEGRATION=1 CL_BASE_URL=http://localhost:8080 CL_IAL_BASE_URL=http://localhost:8081 $(PY_SDK_PYTHON) -m pytest sdk/python/tests -q
	CL_INTEGRATION=1 CL_BASE_URL=http://localhost:8080 CL_IAL_BASE_URL=http://localhost:8081 go test ./sdk/go/contractlane -count=1

sdk-conformance: wait-ready
	bash conformance/runner/run_local_conformance.sh

sdk-sanity:
	@set -euo pipefail; \
	root="$(CURDIR)"; \
	cleanup() { $(MAKE) -C "$$root" down; }; \
	trap cleanup EXIT; \
	$(MAKE) -C "$$root" up; \
	$(MAKE) -C "$$root" sdk-test; \
	$(MAKE) -C "$$root" sdk-conformance; \
	ts_tmp="$$(mktemp -d)"; \
	mkdir -p "$$ts_tmp/node_modules/@contractlane"; \
	ln -s "$$root/sdk/typescript" "$$ts_tmp/node_modules/@contractlane/sdk"; \
	(cd "$$ts_tmp" && node -e "const sdk=require('@contractlane/sdk'); if(!sdk.ContractLaneClient){throw new Error('missing ContractLaneClient export for require')}"); \
	(cd "$$ts_tmp" && node --input-type=module -e "import { ContractLaneClient } from '@contractlane/sdk'; if(!ContractLaneClient){throw new Error('missing ContractLaneClient export for import')}"); \
	py_tmp="$$(mktemp -d)"; \
	python3 -m venv "$$py_tmp/.venv"; \
	PYTHONNOUSERSITE=1 "$$py_tmp/.venv/bin/python" -m pip install -U pip setuptools wheel >/dev/null; \
	PYTHONNOUSERSITE=1 "$$py_tmp/.venv/bin/python" -m pip install "$$root/sdk/python" >/dev/null; \
	PYTHONNOUSERSITE=1 "$$py_tmp/.venv/bin/python" -c "from contractlane import ContractLaneClient, PrincipalAuth; c=ContractLaneClient('http://localhost:8080', PrincipalAuth('tok')); assert c is not None"; \
	trap - EXIT; \
	$(MAKE) -C "$$root" down

logs:
	docker compose -f docker-compose.dev.yml logs -f --tail=200

logs-prod:
	docker compose -f docker-compose.prod.yml logs -f --tail=200

fmt:
	gofmt -w .
