SMP_DATABASE_DIR=database
SMP_REPORTS_DIR=reports
SMP_LOGS_DIR=logs
SMP_BACKUP_DIR=backup

docker-build:
	docker build -t smp:latest .

docker-run:
	docker compose up -d

docker-stop:
	docker compose down

docker-logs:
	docker compose logs -f smp

docker-shell:
	docker exec -it smp /bin/bash

docker-health:
	curl -s http://localhost:8000/api/v6/health | python3 -m json.tool

docker-clean:
	docker compose down -v
	docker image rm smp:latest || true

install:
	chmod +x setup.sh
	./setup.sh

run:
	./run.sh

run-api:
	./venv/bin/python main.py --api

.PHONY: docker-build docker-run docker-stop docker-logs docker-shell docker-health docker-clean install run run-api
