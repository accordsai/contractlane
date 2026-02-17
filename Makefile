SHELL := /bin/bash

.PHONY: up-dev down migrate test smoke logs fmt

up-dev:
	docker compose -f docker-compose.dev.yml up --build -d

down:
	docker compose -f docker-compose.dev.yml down -v

migrate:
	docker compose -f docker-compose.dev.yml run --rm migrate

test:
	go test ./... -count=1

smoke:
	bash scripts/smoke.sh

logs:
	docker compose -f docker-compose.dev.yml logs -f --tail=200

fmt:
	gofmt -w .
