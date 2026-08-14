.PHONY: qa test bench audit clean-qa

qa:
	python3 tools/qa_gate.py

test:
	python3 -m unittest discover -s tests -v

bench:
	python3 tools/bench.py

audit:
	python3 tools/dependency_audit.py

clean-qa:
	rm -f qa-results/latest.json qa-results/latest.md
