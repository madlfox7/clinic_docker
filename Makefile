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
	tests/test_polish.py tests/test_tls.py tests/test_ngrok_demo.py tests/test_audit_chain.py \
	tests/test_audit_status_ui.py tests/test_audit_view.py tests/test_audit_errors.py
PYTEST_ARGS ?= -q
CONFIRM ?=
# yes (with CONFIRM=yes): reset/fclean close the audit chain even when it is
# broken; the registry records it as forced (plan 17 §8.6).
RETIRE_FORCE ?=
# Extra arguments of make audit-verify, e.g. VERIFY_ARGS=--strict
VERIFY_ARGS ?=
# The docker command for "volume inspect" and "volume rm" in reset/fclean: the
# words of $(COMPOSE) before "compose", so the same prefix (sudo -n docker,
# env ... docker) and the same daemon. Empty if COMPOSE has no "compose" word
# (then reset/fclean stop and ask for DOCKER=...). ":=": a DOCKER exported in
# the environment is ignored (another daemon would look like "no such volume");
# only "make ... DOCKER=..." on the command line overrides it.
words_before_compose = $(if $(1),$(if $(filter compose,$(firstword $(1))),,$(firstword $(1)) $(call words_before_compose,$(wordlist 2,$(words $(1)),$(1)))))
DOCKER := $(if $(filter compose,$(COMPOSE)),$(strip $(call words_before_compose,$(COMPOSE))))

.DEFAULT_GOAL := help
.PHONY: help start stop restart restart_up clean reset fclean logs ps test tls-check ngrok ngrok-off audit-verify

# Anonymous volumes mounted by this project's containers (the postgres image
# declares one on the one-shot migrate container). "down -v" misses them once
# "up" has recreated a container, so the wipe targets remove them by name.
define project_anon_volumes
$$(for c in $$($(COMPOSE) ps -aq); do \
	$(DOCKER) inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}' "$$c"; \
done | tr ' ' '\n' | grep -E '^[0-9a-f]{64}$$' | sort -u)
endef

# RETIRE_FORCE=yes is only valid together with CONFIRM=yes; checked before
# anything else runs.
define check_retire_force
@if [ "$(RETIRE_FORCE)" = "yes" ] && [ "$(CONFIRM)" != "yes" ]; then \
	echo "RETIRE_FORCE=yes needs CONFIRM=yes: nothing was changed." >&2; exit 1; \
fi
endef

# The audit anchor volume (docker-compose.yml, audit_anchors): external, so
# "down -v" never removes it. Its name comes from "$(COMPOSE) config"; when the
# daemon says "no such volume" it is created (label clinic.audit=keep, empty:
# the audit_anchor image gives it owner 10002 and mode 700 on the first
# mount). Any other error of "volume inspect" calls fail (defined by the
# caller) and nothing is created. A new volume next to an old ./audit_anchors
# directory gets a warning: the anchors there are not copied (README).
define ensure_anchor_volume
if [ -z "$(DOCKER)" ]; then \
	echo "cannot derive the docker command from COMPOSE='$(COMPOSE)' (no 'compose' word); set DOCKER=... Nothing was changed." >&2; \
	fail; \
fi; \
anchor_volume="$$($(COMPOSE) config | awk '/^volumes:/ {v = 1; next} /^[^ ]/ {v = 0} v && /^  audit_anchors:/ {a = 1; next} v && /^  [^ ]/ {a = 0} a && /^    name:/ {gsub(/["\047]/, "", $$2); print $$2; exit}')"; \
if [ -z "$$anchor_volume" ]; then \
	echo "cannot find the name of the audit anchor volume (audit_anchors) in '$(COMPOSE) config'." >&2; fail; \
fi; \
inspect_err="$$($(DOCKER) volume inspect "$$anchor_volume" 2>&1 >/dev/null)"; inspect_rc=$$?; \
if [ "$$inspect_rc" != 0 ]; then \
	if ! printf '%s\n' "$$inspect_err" | grep -qi 'no such volume'; then \
		echo "cannot tell whether the volume $$anchor_volume exists: $(DOCKER) volume inspect failed (rc=$$inspect_rc):" >&2; \
		printf '%s\n' "$$inspect_err" | head -n 3 | sed 's/^/    /' >&2; \
		fail; \
	fi; \
	echo "$(DOCKER) volume create --label clinic.audit=keep $$anchor_volume   (audit anchors and chain registry)"; \
	$(DOCKER) volume create --label clinic.audit=keep "$$anchor_volume" >/dev/null || fail; \
	if [ -f ./audit_anchors/chains.log ]; then \
		echo "warning ./audit_anchors holds anchors of an older version (bind mount); the new volume $$anchor_volume is empty." >&2; \
		echo "        Copy them into the volume (README, \"Audit anchors in a Docker volume\") before the stand writes there," >&2; \
		echo "        or audit_anchor reports registry_missing. ./audit_anchors is left as it is." >&2; \
	fi; \
fi
endef

# Before down -v, in the same shell line (plan 17 §8.6, Б3): stop proxy and api
# so nothing more is written, then close the open audit chain in the registry
# (anchor.py --retire). A failed retire stops make before down -v. Three cases:
# audit_anchor running -> exec; not running but the database volume exists ->
# a one-off run (starts db and migrate); the volume certainly missing ->
# --offline. "run" has no --no-build; the image is built only when missing.
# The volume is looked up with "$(DOCKER) volume inspect" (name from
# "$(COMPOSE) config"; "docker compose volumes" is missing before Compose
# 2.33). Only "no such volume" counts as missing: any other error (permission
# denied, no daemon, sudo asking for a password) stops make, nothing deleted,
# so the offline retire never skips the chain check by mistake.
# The anchor volume is checked first: a missing one is created empty
# (ensure_anchor_volume; the retire then needs RETIRE_FORCE like before with a
# missing directory), then anchor.py --check-dir in a one-off audit_anchor
# container: /anchors must be 700, owner uid 10002, no ACL, or make stops
# (З-10). down -v keeps the volume (external).
# Then down -v and the anonymous volumes listed above (only this project's).
define wipe_stack
@stopped() { echo "  proxy and api are stopped; $(MAKE) start COMPOSE='$(COMPOSE)' brings the stand back." >&2; }; \
if [ -z "$(DOCKER)" ]; then \
	echo "cannot derive the docker command from COMPOSE='$(COMPOSE)' (no 'compose' word); set DOCKER=... Nothing was changed." >&2; \
	exit 1; \
fi; \
anon="$(project_anon_volumes)"; \
force="$(if $(filter yes,$(RETIRE_FORCE)),--force)"; \
echo "$(COMPOSE) stop proxy api"; $(COMPOSE) stop proxy api || exit 1; \
db_volume="$$($(COMPOSE) config --format json | $(PYTHON) -c 'import json, sys; c = json.load(sys.stdin); print(c.get("volumes", {}).get("db_data", {}).get("name") or c["name"] + "_db_data")')" || { stopped; exit 1; }; \
fail() { echo "  The audit chain was not closed, nothing was deleted." >&2; stopped; exit 1; }; \
$(ensure_anchor_volume); \
echo "$(COMPOSE) run --rm --no-deps -T audit_anchor python anchor.py --check-dir"; \
if ! $(COMPOSE) run --rm --no-deps -T audit_anchor python anchor.py --check-dir; then \
	echo "the anchor volume $$anchor_volume is not 700 / uid 10002; the audit chain was not closed, nothing was deleted." >&2; \
	stopped; exit 1; \
fi; \
if [ -n "$$($(COMPOSE) ps --status running -q audit_anchor 2>/dev/null)" ]; then \
	db_state=running; \
else \
	inspect_err="$$($(DOCKER) volume inspect "$$db_volume" 2>&1 >/dev/null)"; inspect_rc=$$?; \
	if [ "$$inspect_rc" = 0 ]; then \
		db_state=volume; \
	elif printf '%s\n' "$$inspect_err" | grep -qi 'no such volume'; then \
		db_state=none; \
	else \
		echo "cannot tell whether the volume $$db_volume exists: $(DOCKER) volume inspect failed (rc=$$inspect_rc):" >&2; \
		printf '%s\n' "$$inspect_err" | head -n 3 | sed 's/^/    /' >&2; \
		echo "  The audit chain was not closed, nothing was deleted. Check DOCKER='$(DOCKER)' (the same access as COMPOSE)." >&2; \
		stopped; exit 1; \
	fi; \
fi; \
if [ "$$db_state" = running ]; then \
	echo "$(COMPOSE) exec -T audit_anchor python anchor.py --retire $$force"; \
	if ! $(COMPOSE) exec -T audit_anchor python anchor.py --retire $$force; then \
		echo "retire failed: the audit chain was not closed, nothing was deleted." >&2; stopped; exit 1; \
	fi; \
elif [ "$$db_state" = volume ]; then \
	echo "$(COMPOSE) run --rm audit_anchor python anchor.py --retire $$force"; \
	if ! $(COMPOSE) run --rm audit_anchor python anchor.py --retire $$force; then \
		if [ -z "$$force" ]; then \
			echo "retire failed: the audit chain was not closed, nothing was deleted." >&2; \
			echo "  RETIRE_FORCE=yes CONFIRM=yes closes it anyway (offline, forced) if the database cannot start." >&2; \
			stopped; exit 1; \
		fi; \
		echo "RETIRE_FORCE=yes -> offline forced: $(COMPOSE) run --rm --no-deps audit_anchor python anchor.py --retire --offline"; \
		if ! $(COMPOSE) run --rm --no-deps audit_anchor python anchor.py --retire --offline; then \
			echo "offline retire failed: nothing was deleted." >&2; stopped; exit 1; \
		fi; \
	fi; \
else \
	echo "no volume $$db_volume: $(COMPOSE) run --rm --no-deps audit_anchor python anchor.py --retire --offline"; \
	if ! $(COMPOSE) run --rm --no-deps audit_anchor python anchor.py --retire --offline; then \
		echo "offline retire failed: nothing was deleted." >&2; stopped; exit 1; \
	fi; \
fi; \
echo "$(strip $(COMPOSE) down -v $(1))"; $(COMPOSE) down -v $(1) || exit 1; \
for v in $$anon; do \
	if $(DOCKER) volume inspect "$$v" >/dev/null 2>&1; then \
		echo "$(DOCKER) volume rm $$v"; $(DOCKER) volume rm "$$v" >/dev/null || exit 1; \
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
#
# $(1): the "up" arguments. start: --build -d. restart: -d --no-recreate --wait
# after stop, so the services come up in dependency order (db healthy, then
# migrate, audit_prepare, seed, api, proxy), the same containers keep their
# environment (tunnel mode of make ngrok: PUBLIC_BASE_URL, CLINIC_PUBLIC_TUNNEL)
# and make waits until they are running/healthy. "compose restart" restarted
# everything at once: migrate before db, proxy before api.
define start_stack
cp -n .env.example .env
./scripts/init_secrets.sh
@fail() { exit 1; }; $(ensure_anchor_volume)
$(COMPOSE) up $(1)
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
	@echo "  restart  stop, then start the same containers in dependency order and wait until healthy (no rebuild, tunnel mode kept)"
	@echo "  clean    remove containers and networks; data is kept"
	@echo "  logs     follow the logs of all services"
	@echo "  ps       list the containers"
	@echo "  tls-check check the proxy certificate, SAN, chain and ports as Compose will use them (read-only)"
	@echo "  ngrok    public demo: start with PUBLIC_BASE_URL=https://\$$NGROK_DOMAIN (tunnel mode), then run ngrok to the HTTPS port"
	@echo "  ngrok-off start again with the .env address (tunnel off)"
	@echo "  test     run the test suite (TEST_BASE, TEST_CA, TEST_MAILPIT, TEST_PROJECT, PYTHON, PYTEST_ARGS)"
	@echo "  audit-verify check the audit hash chain, anchors and registry (VERIFY_ARGS=--strict: forced retires fail)"
	@echo "  reset    WIPES THE DATABASE: down -v, then start (asks first; CONFIRM=yes skips)"
	@echo "  fclean   WIPES THE DATABASE: down -v --rmi local --remove-orphans for this project only (asks first; CONFIRM=yes skips)"
	@echo "  RETIRE_FORCE=yes  with CONFIRM=yes: reset/fclean even if the audit chain is broken (logged as forced)"
	@echo "  DOCKER   docker command of reset/fclean (COMPOSE before 'compose', or make ... DOCKER=...; not from the environment; now: $(DOCKER))"

start:
	$(call start_stack,--build -d)

stop:
	$(COMPOSE) stop

restart:
	$(COMPOSE) stop
	@$(MAKE) --no-print-directory restart_up || { \
		echo "restart: a service did not come up running/healthy (see: make ps; make logs; make audit-verify)." >&2; \
		exit 1; }

# not for direct use: the "up" half of restart
restart_up:
	$(call start_stack,-d --no-recreate --wait)

clean:
	$(COMPOSE) down

reset:
	$(check_retire_force)
	$(confirm_wipe)
	$(call wipe_stack)
	$(call start_stack,--build -d)

fclean:
	$(check_retire_force)
	$(confirm_wipe)
	$(call wipe_stack,--rmi local --remove-orphans)

logs:
	$(COMPOSE) logs -f

# Independent check of the audit chain inside audit_anchor (key and anchors are there).
audit-verify:
	$(COMPOSE) exec -T audit_anchor python verify_audit.py $(VERIFY_ARGS)

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
