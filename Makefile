# Docker Compose lifecycle and tests for this project.
# Every target goes through $(COMPOSE), so another project name works too:
#   make start COMPOSE="docker compose -p planera"

COMPOSE ?= docker compose
PYTHON ?= python3
TEST_BASE ?= http://localhost:8080
TEST_MAILPIT ?= http://127.0.0.1:8025
# Compose project the tests inspect (docker compose exec ...); empty = default.
TEST_PROJECT ?=
TEST_FILES ?= tests/test_stage4.py tests/test_rls_boundary.py tests/test_secrets.py \
	tests/test_field_encryption.py tests/test_ui_security.py tests/test_ui_fixes.py \
	tests/test_audit_fixes.py tests/test_session.py tests/test_network.py
PYTEST_ARGS ?= -q
CONFIRM ?=

.DEFAULT_GOAL := help
.PHONY: help start stop restart clean reset fclean logs ps test

# Anonymous volumes mounted by this project's containers (the postgres image
# declares one on the one-shot migrate container). "down -v" misses them once
# "up" has recreated a container, so the wipe targets remove them by name.
define project_anon_volumes
$$(for c in $$($(COMPOSE) ps -aq); do \
	docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}' "$$c"; \
done | tr ' ' '\n' | grep -E '^[0-9a-f]{64}$$' | sort -u)
endef

# down -v, then remove the anonymous volumes listed above (only this project's).
define wipe_stack
@anon="$(project_anon_volumes)"; \
echo "$(strip $(COMPOSE) down -v $(1))"; $(COMPOSE) down -v $(1) || exit 1; \
for v in $$anon; do \
	if docker volume inspect "$$v" >/dev/null 2>&1; then \
		echo "docker volume rm $$v"; docker volume rm "$$v" >/dev/null || exit 1; \
	fi; \
done
endef

# Asks before a step that deletes the database volume; CONFIRM=yes skips the question.
define confirm_wipe
@if [ "$(CONFIRM)" != "yes" ]; then \
	printf '%s\n' "WARNING: '$@' deletes the database volume of '$(COMPOSE)'. All data will be lost."; \
	printf '%s' "Type yes to continue: "; \
	read answer || answer=; \
	if [ "$$answer" != "yes" ]; then echo "Aborted: nothing was changed."; exit 1; fi; \
fi
endef

define start_stack
cp -n .env.example .env
./scripts/init_secrets.sh
$(COMPOSE) up --build -d
endef

help:
	@echo "Targets (COMPOSE=\"$(COMPOSE)\"):"
	@echo "  help     show this list (default)"
	@echo "  start    create .env and secrets if missing, build and start; data is kept"
	@echo "  stop     stop the containers"
	@echo "  restart  restart the containers"
	@echo "  clean    remove containers and networks; data is kept"
	@echo "  logs     follow the logs of all services"
	@echo "  ps       list the containers"
	@echo "  test     run the test suite (TEST_BASE, TEST_MAILPIT, TEST_PROJECT, PYTHON, PYTEST_ARGS)"
	@echo "  reset    WIPES THE DATABASE: down -v, then start (asks first; CONFIRM=yes skips)"
	@echo "  fclean   WIPES THE DATABASE: down -v --rmi local --remove-orphans for this project only (asks first; CONFIRM=yes skips)"

start:
	$(start_stack)

stop:
	$(COMPOSE) stop

restart:
	$(COMPOSE) restart

clean:
	$(COMPOSE) down

reset:
	$(confirm_wipe)
	$(call wipe_stack)
	$(start_stack)

fclean:
	$(confirm_wipe)
	$(call wipe_stack,--rmi local --remove-orphans)

logs:
	$(COMPOSE) logs -f

ps:
	$(COMPOSE) ps

test:
	$(if $(TEST_PROJECT),COMPOSE_PROJECT_NAME=$(TEST_PROJECT)) CLINIC_TEST_BASE=$(TEST_BASE) CLINIC_MAILPIT=$(TEST_MAILPIT) \
		$(PYTHON) -m pytest $(PYTEST_ARGS) $(TEST_FILES)
