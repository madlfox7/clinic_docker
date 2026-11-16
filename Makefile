# Docker Compose lifecycle and tests for this project.
# Every target goes through $(COMPOSE), so another project name works too:
#   make start COMPOSE="docker compose -p planera"

COMPOSE ?= docker compose
PYTHON ?= python3
TEST_BASE ?= https://localhost:8450
# CA the tests verify the stand certificate against (SSL_CERT_FILE for pytest only).
TEST_CA ?= secrets/tls/ca.crt
TEST_MAILPIT ?= http://127.0.0.1:8025
# Compose project the tests inspect (docker compose exec ...); empty = default.
TEST_PROJECT ?=
TEST_FILES ?= tests/test_stage4.py tests/test_rls_boundary.py tests/test_secrets.py \
	tests/test_field_encryption.py tests/test_ui_security.py tests/test_ui_fixes.py \
	tests/test_audit_fixes.py tests/test_session.py tests/test_network.py \
	tests/test_r2_fixes.py tests/test_ux_filters.py tests/test_hardening.py \
	tests/test_polish.py tests/test_tls.py tests/test_ngrok_demo.py tests/test_audit_chain.py
PYTEST_ARGS ?= -q
CONFIRM ?=

.DEFAULT_GOAL := help
.PHONY: help start stop restart clean reset fclean logs ps test tls-check ngrok ngrok-off

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

# A server certificate reissued by init_secrets.sh is written into the same
# files the running proxy has mounted; nginx only reads them on (re)load, so
# a proxy that "up" did not recreate is reloaded here (graceful, plan 5.6).
define start_stack
cp -n .env.example .env
./scripts/init_secrets.sh
$(COMPOSE) up --build -d
@if [ -e secrets/tls/.leaf_reissued ]; then \
	echo "$(COMPOSE) exec -T proxy nginx -s reload   (new server certificate)"; \
	reloaded=no; \
	for attempt in 1 2 3 4 5 6 7 8 9 10; do \
		if $(COMPOSE) exec -T proxy nginx -s reload >/dev/null 2>&1; then reloaded=yes; break; fi; \
		sleep 1; \
	done; \
	if [ "$$reloaded" = yes ]; then \
		rm -f secrets/tls/.leaf_reissued; \
	else \
		echo "warning the proxy did not reload; it may still serve the old certificate." >&2; \
		echo "        Run: $(COMPOSE) exec proxy nginx -s reload  (or restart the proxy)" >&2; \
	fi; \
fi
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
	@echo "  tls-check check the proxy certificate, SAN, chain and ports as Compose will use them (read-only)"
	@echo "  ngrok    public demo: start with PUBLIC_BASE_URL=https://\$$NGROK_DOMAIN (tunnel mode), then run ngrok to the HTTPS port"
	@echo "  ngrok-off start again with the .env address (tunnel off)"
	@echo "  test     run the test suite (TEST_BASE, TEST_CA, TEST_MAILPIT, TEST_PROJECT, PYTHON, PYTEST_ARGS)"
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
	$(if $(TEST_PROJECT),COMPOSE_PROJECT_NAME=$(TEST_PROJECT)) CLINIC_TEST_BASE=$(TEST_BASE) CLINIC_MAILPIT=$(TEST_MAILPIT) SSL_CERT_FILE=$(TEST_CA) \
		$(PYTHON) -m pytest $(PYTEST_ARGS) $(TEST_FILES)

# Ports and environment come from $(COMPOSE) config (override files and shell
# variables included), not from a grep of .env.
tls-check:
	$(COMPOSE) config --format json | $(PYTHON) scripts/tls_compose_env.py

# Public demo through ngrok (README, Demo via ngrok). The tunnel settings go to
# "make start" through the environment; .env is not edited.
ngrok:
	COMPOSE="$(COMPOSE)" MAKE="$(MAKE)" PYTHON="$(PYTHON)" ./scripts/ngrok_demo.sh on

ngrok-off:
	COMPOSE="$(COMPOSE)" MAKE="$(MAKE)" PYTHON="$(PYTHON)" ./scripts/ngrok_demo.sh off
