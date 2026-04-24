# mTLS ED25519 API — project lifecycle automation.
#
# Tested on Linux (Ubuntu/Debian) with GNU make and on macOS with Homebrew
# `make` (GNU). Apple's stock `/usr/bin/make` is GNU on modern macOS, so
# `make <target>` should work out of the box there too.
#
# Quickstart — see README.md for the full walkthrough:
#
#   make help       # list targets
#   make pki        # generate ED25519 CA + server + client certs
#   make server     # start the mTLS server in the background
#   make test       # run the full test matrix
#   make stop       # stop the background server

SHELL        := /usr/bin/env bash
.SHELLFLAGS  := -euo pipefail -c

VENV         := venv
PY           := $(VENV)/bin/python
PIP          := $(VENV)/bin/pip

PID_FILE     := .server.pid
SERVER_LOG   := .server.log

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
# Fail early when a target that actually uses Python is invoked without a
# venv. Scoping by $(MAKECMDGOALS) so bare `make`, `make help`, `make clean`,
# `make pki`, `make revoke`, `make renew`, and `make pin` all stay usable on
# a clean clone that hasn't built its venv yet — they shell out to openssl /
# bash / awk and never touch Python.
VENV_REQUIRED_GOALS := server test test-unit test-integration test-cov test-all
ifneq ($(filter $(VENV_REQUIRED_GOALS),$(MAKECMDGOALS)),)
ifeq (,$(wildcard $(PY)))
$(error Python venv not found at '$(VENV)/'. Run: python -m venv venv && source venv/bin/activate && pip install -r requirements-dev.txt)
endif
endif

# --- Phony declarations -----------------------------------------------------
.PHONY: help pki server stop test test-unit test-integration test-cov test-all nginx-check nginx-start nginx-stop nginx-reload nginx-server nginx-stop-all test-nginx bench-nginx stress-nginx load-test-nginx test-full stack verify-full revoke renew pin clean

# Default target is `help` so a bare `make` tells you what's available.
.DEFAULT_GOAL := help

# --- Targets ----------------------------------------------------------------

help:  ## Show this help
	@printf '%bmTLS ED25519 API — available targets:%b\n' "$(C_BOLD)" "$(C_RESET)"
	@awk 'BEGIN {FS=":.*## "} /^[a-z][a-zA-Z_-]*:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

pki:  ## Generate or regenerate the full PKI (CA + server + client + CRL)
	$(call INFO,running pki_setup.sh)
	@./pki_setup.sh
	$(call INFO,pki ready)

server:  ## Start the FastAPI server in the background (PID -> $(PID_FILE))
	@if [[ -f $(PID_FILE) ]] && kill -0 "$$(cat $(PID_FILE))" 2>/dev/null; then \
		printf '%b[make]%b server already running (pid %s)\n' \
			"$(C_YELLOW)" "$(C_RESET)" "$$(cat $(PID_FILE))"; \
		exit 0; \
	fi
	$(call INFO,starting server in background -> $(SERVER_LOG))
	@$(PY) server.py > $(SERVER_LOG) 2>&1 & echo $$! > $(PID_FILE)
	@for _ in 1 2 3 4 5 6 7 8 9 10; do \
		if curl --silent --fail \
				--cacert pki/ca/ca.crt \
				--cert pki/client/client.crt \
				--key pki/client/client.key \
				https://localhost:8443/health >/dev/null 2>&1; then \
			printf '%b[make]%b server ready on https://127.0.0.1:8443\n' \
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

stop:  ## Stop the background server (no-op if not running)
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

test:  ## Run the full test suite (pytest unit + integration + curl matrix)
	$(call INFO,pytest — unit + integration)
	@$(PY) -m pytest
	$(call INFO,curl_tests.sh)
	@./tests/curl_tests.sh
	$(call INFO,negative_tests.sh)
	@./tests/negative_tests.sh

test-unit:  ## Run only pytest unit tests (no network, no subprocess)
	$(call INFO,pytest -m unit)
	@$(PY) -m pytest -m unit

test-integration:  ## Run only pytest integration tests (starts server subprocess)
	$(call INFO,pytest -m integration)
	@$(PY) -m pytest -m integration

test-cov:  ## Run full pytest with coverage (HTML at htmlcov/, threshold in .coveragerc)
	$(call INFO,pytest --cov — branch coverage, fail_under=70)
	@$(PY) -m pytest \
		--cov=server --cov=middleware --cov=tls --cov=config \
		--cov-report=html --cov-report=term-missing
	$(call INFO,HTML report at htmlcov/index.html)

test-all:  ## Run unit tests then integration tests (sequential, distinct markers)
	@$(MAKE) --no-print-directory test-unit
	@$(MAKE) --no-print-directory test-integration

# --- N1: nginx termination layer --------------------------------------------

NGINX_TEST_CONF := nginx/nginx-test.conf

nginx-check:  ## Regenerate nginx-test.conf and run `nginx -t` on it
	$(call INFO,nginx-test-gen.sh + nginx -t)
	@bash nginx/nginx-test-gen.sh
	@nginx -t -c $(PWD)/$(NGINX_TEST_CONF)

nginx-start:  ## Start nginx with the local test config (foreground-capable)
	$(call INFO,starting nginx -c $(NGINX_TEST_CONF))
	@nginx -c $(PWD)/$(NGINX_TEST_CONF)

nginx-stop:  ## Send SIGQUIT to the running nginx (graceful drain)
	$(call INFO,stopping nginx -s quit)
	@nginx -c $(PWD)/$(NGINX_TEST_CONF) -s quit 2>/dev/null || \
		printf '%b[make]%b nginx not running (or already stopped)\n' \
		"$(C_YELLOW)" "$(C_RESET)"

nginx-reload:  ## Reload nginx config (HUP) after editing nginx.conf
	$(call INFO,nginx -s reload)
	@bash nginx/nginx-test-gen.sh
	@nginx -c $(PWD)/$(NGINX_TEST_CONF) -s reload

nginx-server:  ## Start nginx AND the FastAPI server with NGINX_MODE=true
	@$(MAKE) --no-print-directory nginx-start
	@NGINX_MODE=true $(MAKE) --no-print-directory server

nginx-stop-all:  ## Stop both nginx and the FastAPI server
	@$(MAKE) --no-print-directory nginx-stop
	@$(MAKE) --no-print-directory stop

test-nginx:  ## Run the N3 nginx auth suite (27 tests across A..F)
	$(call INFO,pytest tests/test_nginx_auth.py)
	@$(PY) -m pytest tests/test_nginx_auth.py -v
	$(call INFO,nginx_auth_matrix.sh)
	@bash tests/nginx_auth_matrix.sh --quiet

bench-nginx:  ## N4 — pytest-benchmark handshake-cost suite (NP1..NP4)
	$(call INFO,pytest -m performance tests/test_nginx_perf.py)
	@$(PY) -m pytest -m performance tests/test_nginx_perf.py

stress-nginx:  ## N4 — concurrency stress (NC1..NC4, slow)
	$(call INFO,pytest -m slow tests/test_nginx_concurrency.py)
	@$(PY) -m pytest -m slow tests/test_nginx_concurrency.py

test-full:  ## Run the standard test suite AND the nginx auth suite
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory test-nginx

stack:  ## Generate PKI and start the full nginx + FastAPI stack
	@$(MAKE) --no-print-directory pki
	@$(MAKE) --no-print-directory nginx-server

verify-full:  ## Run every N1..N4 exit criterion, print PASS/FAIL, exit 1 on fail
	@bash -eu -o pipefail -c '\
	  fail=0; \
	  run() { local name="$$1"; shift; \
	    if eval "$$@" >/dev/null 2>&1; then \
	      printf "%b[PASS]%b %s\n" "$(C_GREEN)" "$(C_RESET)" "$$name"; \
	    else \
	      printf "%b[FAIL]%b %s\n" "$(C_RED)" "$(C_RESET)" "$$name"; \
	      fail=1; \
	    fi; \
	  }; \
	  run "N1 nginx -t"                   "bash nginx/nginx-test-gen.sh && nginx -t -c $(PWD)/nginx/nginx-test.conf"; \
	  run "N1 nginx cert is Ed25519"     "openssl x509 -in pki/nginx/nginx.crt -noout -text | grep -q ED25519"; \
	  run "N1 nginx cert verifies"       "openssl verify -CAfile pki/ca/ca.crt pki/nginx/nginx.crt"; \
	  run "N1 nginx.key chmod 640"       "[[ \"$$(stat -c %a pki/nginx/nginx.key)\" == 640 ]]"; \
	  run "N2 middleware unit tests"     "$(PY) -m pytest tests/test_middleware.py -q"; \
	  run "N3 nginx auth suite"          "$(PY) -m pytest tests/test_nginx_auth.py -q"; \
	  run "N4 nginx benchmarks"          "$(PY) -m pytest -m performance tests/test_nginx_perf.py -q"; \
	  run "N4 nginx concurrency"         "$(PY) -m pytest tests/test_nginx_concurrency.py -q"; \
	  exit $$fail'

load-test-nginx:  ## N4 — Locust load through nginx (60s, 50 users, SLO gate)
	$(call INFO,locust -f tests/nginx_locustfile.py)
	@$(VENV)/bin/locust -f tests/nginx_locustfile.py --headless \
		-u 50 --spawn-rate 10 --run-time 60s \
		--host https://localhost:8444 --exit-code-on-error 1
	$(call INFO,load test passed — see stdout for p95/p99)

revoke:  ## Revoke client-01 and regenerate the CRL (server restart needed after)
	$(call INFO,revoking pki/client/client.crt)
	@./tests/revoke_client.sh
	$(call WARN,CRL updated. Run: make stop && make server  — to apply.)

renew:  ## Rotate pki/client/client.crt to a fresh 24h-lived cert
	$(call INFO,renewing client cert)
	@./renew_client_cert.sh

pin:  ## Extract server cert SHA-256 fingerprint into pki/server/server.fingerprint
	@if [[ ! -f pki/server/server.crt ]]; then \
		printf '%b[make]%b pki/server/server.crt missing — run `make pki` first\n' \
			"$(C_RED)" "$(C_RESET)" >&2; \
		exit 1; \
	fi
	@openssl x509 -in pki/server/server.crt -noout -fingerprint -sha256 \
		> pki/server/server.fingerprint
	$(call INFO,pin written to pki/server/server.fingerprint:)
	@cat pki/server/server.fingerprint

clean:  ## Remove generated PKI artifacts, Python caches, server logs
	$(call INFO,cleaning)
	@$(MAKE) --no-print-directory stop
	@rm -rf pki/ca/ca.key pki/ca/ca.crt pki/ca/ca.srl pki/ca/ca.crl \
	        pki/ca/index.txt* pki/ca/serial* pki/ca/crlnumber* pki/ca/newcerts
	@rm -rf pki/server/server.key pki/server/server.crt pki/server/server.csr \
	        pki/server/server.fingerprint
	@rm -rf pki/client/client.key pki/client/client.crt pki/client/client.csr
	@find . -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
	@rm -f $(SERVER_LOG) $(PID_FILE)
	$(call INFO,done)
