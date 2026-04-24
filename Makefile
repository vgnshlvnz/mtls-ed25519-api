# mTLS ED25519 API — project lifecycle automation (v1.2).
#
# Tested on Linux (Ubuntu/Debian) with GNU make and on macOS with Homebrew
# `make` (GNU). Apple's stock `/usr/bin/make` is GNU on modern macOS, so
# `make <target>` should work out of the box there too.
#
# v1.2 architecture:
#   make pki           -> CA + server + nginx + client certs
#   make server        -> FastAPI on plain HTTP :8443 (auth-blind)
#   make nginx-config  -> regenerate nginx-test.conf from the template
#   make nginx-start   -> start nginx on :8444 (mTLS + CN allowlist)
#   make stack         -> server + nginx together (client-facing :8444)
#   make test          -> pytest (unit + integration markers)
#   make stop          -> stop FastAPI + nginx
#
# See README.md for the full walkthrough.

SHELL        := /usr/bin/env bash
.SHELLFLAGS  := -euo pipefail -c

VENV         := venv
PY           := $(VENV)/bin/python
PIP          := $(VENV)/bin/pip

PID_FILE        := .server.pid
SERVER_LOG      := .server.log
NGINX_CONF      := nginx/nginx-test.conf
NGINX_PID       := nginx/logs/nginx.pid
NGINX_LOG       := .nginx.log
APACHE_CONF     := apache/apache-test.conf
APACHE_DIR_ABS  := $(shell pwd)/apache
APACHE_PID      := apache/logs/apache.pid
APACHE_LOG      := .apache.log

# ANSI colour escapes. Quoted via printf '%b' in recipes so they don't
# bleed into logs when stdout is not a TTY.
C_GREEN      := \033[32m
C_YELLOW     := \033[33m
C_RED        := \033[31m
C_BOLD       := \033[1m
C_RESET      := \033[0m

define INFO
	@printf '%b[make]%b %s\n' "$(C_GREEN)" "$(C_RESET)" "$(1)"
endef

define WARN
	@printf '%b[make]%b %s\n' "$(C_YELLOW)" "$(C_RESET)" "$(1)" >&2
endef

# --- Guards -----------------------------------------------------------------
VENV_REQUIRED_GOALS := server test test-unit test-integration test-cov test-all stack stack-apache apache-server
ifneq ($(filter $(VENV_REQUIRED_GOALS),$(MAKECMDGOALS)),)
ifeq (,$(wildcard $(PY)))
$(error Python venv not found at '$(VENV)/'. Run: python -m venv venv && source venv/bin/activate && pip install -r requirements-dev.txt)
endif
endif

# --- Phony declarations -----------------------------------------------------
.PHONY: help pki server stop test test-unit test-integration test-cov test-all \
        test-apache \
        revoke renew pin clean \
        nginx-config nginx-start nginx-stop nginx-reload stack \
        apache-check apache-start apache-stop apache-reload apache-server \
        apache-stop-all stack-apache

.DEFAULT_GOAL := help

# --- Targets ----------------------------------------------------------------

help:  ## Show this help
	@printf '%bmTLS ED25519 API — available targets:%b\n' "$(C_BOLD)" "$(C_RESET)"
	@awk 'BEGIN {FS=":.*## "} /^[a-z][a-zA-Z_-]*:.*## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

pki:  ## Generate or regenerate the full PKI (CA + server + nginx + client + CRL)
	$(call INFO,running pki_setup.sh)
	@./pki_setup.sh
	$(call INFO,pki ready)

server:  ## Start FastAPI plain-HTTP on :8443 (PID -> $(PID_FILE))
	@if [[ -f $(PID_FILE) ]] && kill -0 "$$(cat $(PID_FILE))" 2>/dev/null; then \
		printf '%b[make]%b server already running (pid %s)\n' \
			"$(C_YELLOW)" "$(C_RESET)" "$$(cat $(PID_FILE))"; \
		exit 0; \
	fi
	$(call INFO,starting FastAPI (plain HTTP) in background -> $(SERVER_LOG))
	@$(PY) server.py > $(SERVER_LOG) 2>&1 & echo $$! > $(PID_FILE)
	@for _ in 1 2 3 4 5 6 7 8 9 10; do \
		if curl --silent --fail http://127.0.0.1:8443/health >/dev/null 2>&1; then \
			printf '%b[make]%b FastAPI ready on http://127.0.0.1:8443 (auth-blind)\n' \
				"$(C_GREEN)" "$(C_RESET)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	printf '%b[make]%b server did not become ready. Log tail:\n' \
		"$(C_RED)" "$(C_RESET)" >&2; \
	tail -20 $(SERVER_LOG) >&2; \
	if [[ -f $(PID_FILE) ]]; then \
		kill "$$(cat $(PID_FILE))" 2>/dev/null || true; \
		sleep 1; \
		kill -9 "$$(cat $(PID_FILE))" 2>/dev/null || true; \
		rm -f $(PID_FILE); \
	fi; \
	exit 1

stop:  ## Stop the background FastAPI server (no-op if not running)
	@if [[ ! -f $(PID_FILE) ]]; then \
		printf '%b[make]%b no $(PID_FILE); server not running\n' \
			"$(C_YELLOW)" "$(C_RESET)"; \
	else \
		pid=$$(cat $(PID_FILE)); \
		if kill -0 "$$pid" 2>/dev/null; then \
			printf '%b[make]%b stopping server (pid %s)\n' \
				"$(C_GREEN)" "$(C_RESET)" "$$pid"; \
			kill "$$pid" 2>/dev/null || true; \
			for _ in 1 2 3 4 5; do kill -0 "$$pid" 2>/dev/null || break; sleep 1; done; \
			kill -9 "$$pid" 2>/dev/null || true; \
		else \
			printf '%b[make]%b pid %s is already gone\n' \
				"$(C_YELLOW)" "$(C_RESET)" "$$pid"; \
		fi; \
		rm -f $(PID_FILE); \
	fi

nginx-config:  ## Regenerate nginx/nginx-test.conf from the tracked template
	$(call INFO,generating $(NGINX_CONF) from nginx/nginx.conf)
	@./nginx/nginx-test-gen.sh >/dev/null
	$(call INFO,validating with nginx -t)
	@nginx -t -c "$$(pwd)/$(NGINX_CONF)" 2>&1 | sed 's/^/    /'

nginx-start: nginx-config  ## Start nginx on :8444 (mTLS + CN allowlist)
	@if [[ -f $(NGINX_PID) ]] && kill -0 "$$(cat $(NGINX_PID))" 2>/dev/null; then \
		printf '%b[make]%b nginx already running (pid %s)\n' \
			"$(C_YELLOW)" "$(C_RESET)" "$$(cat $(NGINX_PID))"; \
		exit 0; \
	fi
	$(call INFO,starting nginx in background -> $(NGINX_LOG))
	@mkdir -p nginx/logs
	@nginx -c "$$(pwd)/$(NGINX_CONF)" > $(NGINX_LOG) 2>&1 &
	@for _ in 1 2 3 4 5; do \
		if [[ -f $(NGINX_PID) ]]; then \
			printf '%b[make]%b nginx ready on https://127.0.0.1:8444 (mTLS + CN allowlist)\n' \
				"$(C_GREEN)" "$(C_RESET)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	printf '%b[make]%b nginx did not come up; check $(NGINX_LOG)\n' \
		"$(C_RED)" "$(C_RESET)" >&2; \
	exit 1

nginx-stop:  ## Stop the background nginx
	@if [[ -f $(NGINX_PID) ]]; then \
		pid=$$(cat $(NGINX_PID)); \
		if kill -0 "$$pid" 2>/dev/null; then \
			printf '%b[make]%b stopping nginx (pid %s)\n' \
				"$(C_GREEN)" "$(C_RESET)" "$$pid"; \
			nginx -s quit -c "$$(pwd)/$(NGINX_CONF)" 2>/dev/null || kill "$$pid" 2>/dev/null || true; \
		fi; \
		rm -f $(NGINX_PID); \
	else \
		printf '%b[make]%b nginx not running\n' "$(C_YELLOW)" "$(C_RESET)"; \
	fi

nginx-reload: nginx-config  ## Hot-reload nginx (re-reads ca.crl + CN allowlist)
	@if [[ ! -f $(NGINX_PID) ]]; then \
		printf '%b[make]%b nginx not running; use `make nginx-start`\n' \
			"$(C_RED)" "$(C_RESET)" >&2; \
		exit 1; \
	fi
	$(call INFO,sending SIGHUP to nginx)
	@nginx -s reload -c "$$(pwd)/$(NGINX_CONF)"

stack: server nginx-start  ## Start FastAPI + nginx together (client hits :8444)
	$(call INFO,stack up — client -> https://127.0.0.1:8444 -> http://127.0.0.1:8443)

# --- Apache (v1.3) ----------------------------------------------------------

apache-check:  ## Generate apache-test.conf + run apachectl -t (v1.3)
	$(call INFO,generating $(APACHE_CONF) from apache/apache.conf)
	@./apache/apache-test-gen.sh >/dev/null
	$(call INFO,validating with apachectl -t)
	@apachectl -t -f "$$(pwd)/$(APACHE_CONF)" -d "$(APACHE_DIR_ABS)" 2>&1 | sed 's/^/    /'

apache-start: apache-check  ## Start Apache on :8445 (mTLS + RewriteMap CN allowlist)
	@if [[ -f $(APACHE_PID) ]] && kill -0 "$$(cat $(APACHE_PID))" 2>/dev/null; then \
		printf '%b[make]%b apache already running (pid %s)\n' \
			"$(C_YELLOW)" "$(C_RESET)" "$$(cat $(APACHE_PID))"; \
		exit 0; \
	fi
	$(call INFO,starting Apache in background -> $(APACHE_LOG))
	@apachectl -f "$$(pwd)/$(APACHE_CONF)" -d "$(APACHE_DIR_ABS)" -k start > $(APACHE_LOG) 2>&1
	@for _ in 1 2 3 4 5; do \
		if [[ -f $(APACHE_PID) ]]; then \
			printf '%b[make]%b apache ready on https://127.0.0.1:8445 (mTLS + RewriteMap)\n' \
				"$(C_GREEN)" "$(C_RESET)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	printf '%b[make]%b apache did not come up; check $(APACHE_LOG) and apache/logs/error.log\n' \
		"$(C_RED)" "$(C_RESET)" >&2; \
	exit 1

apache-stop:  ## Stop Apache
	@if [[ -f $(APACHE_PID) ]]; then \
		printf '%b[make]%b stopping apache (pid %s)\n' "$(C_GREEN)" "$(C_RESET)" "$$(cat $(APACHE_PID))"; \
		apachectl -f "$$(pwd)/$(APACHE_CONF)" -d "$(APACHE_DIR_ABS)" -k stop 2>/dev/null || \
			kill "$$(cat $(APACHE_PID))" 2>/dev/null || true; \
		rm -f $(APACHE_PID); \
	else \
		printf '%b[make]%b apache not running\n' "$(C_YELLOW)" "$(C_RESET)"; \
	fi

apache-reload: apache-check  ## Hot-reload Apache (re-reads cn_allowlist.txt + ca.crl)
	@if [[ ! -f $(APACHE_PID) ]]; then \
		printf '%b[make]%b apache not running; use `make apache-start`\n' \
			"$(C_RED)" "$(C_RESET)" >&2; \
		exit 1; \
	fi
	$(call INFO,sending USR1 (graceful) to apache)
	@apachectl -f "$$(pwd)/$(APACHE_CONF)" -d "$(APACHE_DIR_ABS)" -k graceful

apache-server: server apache-start  ## Start FastAPI + Apache together
	$(call INFO,apache stack up — client -> https://127.0.0.1:8445 -> http://127.0.0.1:8443)

apache-stop-all: apache-stop stop  ## Stop both Apache and FastAPI

stack-apache: pki apache-server  ## One-shot: pki + FastAPI + Apache

test:  ## Run the pytest test suite (unit + integration markers)
	$(call INFO,pytest — unit + integration)
	@$(PY) -m pytest

test-unit:  ## Run only pytest unit tests (no network, no subprocess)
	$(call INFO,pytest -m unit)
	@$(PY) -m pytest -m unit

test-integration:  ## Run only pytest integration tests (starts server subprocess)
	$(call INFO,pytest -m integration)
	@$(PY) -m pytest -m integration

test-cov:  ## Run full pytest with coverage (HTML at htmlcov/)
	$(call INFO,pytest --cov — branch coverage)
	@$(PY) -m pytest \
		--cov=server --cov=config \
		--cov-report=html --cov-report=term-missing
	$(call INFO,HTML report at htmlcov/index.html)

test-all:  ## Run unit tests then integration tests (sequential, distinct markers)
	@$(MAKE) --no-print-directory test-unit
	@$(MAKE) --no-print-directory test-integration

test-apache:  ## Run the Apache auth pytest suite (v1.3, 27 tests)
	$(call INFO,pytest tests/test_apache_auth.py)
	@$(PY) -m pytest tests/test_apache_auth.py -v

revoke:  ## Revoke client-01 and regenerate the CRL (nginx reload needed after)
	$(call INFO,revoking pki/client/client.crt)
	@./tests/revoke_client.sh
	$(call WARN,CRL updated. Run: make nginx-reload  — to apply.)

renew:  ## Rotate pki/client/client.crt to a fresh 24h-lived cert
	$(call INFO,renewing client cert)
	@./renew_client_cert.sh

pin:  ## Extract nginx cert SHA-256 fingerprint into pki/nginx/nginx.fingerprint
	@if [[ ! -f pki/nginx/nginx.crt ]]; then \
		printf '%b[make]%b pki/nginx/nginx.crt missing — run `make pki` first\n' \
			"$(C_RED)" "$(C_RESET)" >&2; \
		exit 1; \
	fi
	@openssl x509 -in pki/nginx/nginx.crt -noout -fingerprint -sha256 \
		> pki/nginx/nginx.fingerprint
	$(call INFO,pin written to pki/nginx/nginx.fingerprint:)
	@cat pki/nginx/nginx.fingerprint

clean:  ## Remove generated PKI artifacts, Python caches, server logs
	$(call INFO,cleaning)
	@$(MAKE) --no-print-directory nginx-stop || true
	@$(MAKE) --no-print-directory stop
	@rm -rf pki/ca/ca.key pki/ca/ca.crt pki/ca/ca.srl pki/ca/ca.crl \
	        pki/ca/index.txt* pki/ca/serial* pki/ca/crlnumber* pki/ca/newcerts
	@rm -rf pki/server/server.key pki/server/server.crt pki/server/server.csr \
	        pki/server/server.fingerprint
	@rm -rf pki/nginx/nginx.key pki/nginx/nginx.crt pki/nginx/nginx.csr \
	        pki/nginx/nginx.fingerprint
	@rm -rf pki/client/client.key pki/client/client.crt pki/client/client.csr
	@rm -rf nginx/nginx-test.conf nginx/logs
	@find . -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
	@rm -f $(SERVER_LOG) $(PID_FILE) $(NGINX_LOG)
	$(call INFO,done)
