PYTHON ?= python3

.PHONY: check check-full clean

check:
	$(PYTHON) lotrs-py/check_parameters.py
	@set -e; for t in ring sample params lotrs codec wtilde e2e; do $(PYTHON) lotrs-py/test_$$t.py; done
	$(PYTHON) lotrs-py/vectors.py --verify lotrs-py/vectors.json
	$(PYTHON) lotrs-py/revised_lattice_kat.py
	cd lotrs-rs && cargo test --release

check-full: check
	cd lotrs-rs && cargo test --release --test interop -- --ignored bench_and_production_signing_round_trip
	$(MAKE) -C estimator test

clean:
	cd lotrs-rs && cargo clean
	cd lotrs-py && $(MAKE) clean
	cd estimator && $(MAKE) clean
