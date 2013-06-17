.PHONY: all test clean_coverage clean pep8 pyflakes check 

all:
	@echo 'test           run the unit tests'
	@echo 'coverage       generate coverage statistics'
	@echo 'flake8         check for PEP8 compliance and unused imports'
	@echo 'check          make sure you are ready to commit'
	@echo 'clean          cleanup the source tree'

test: clean_coverage
	@echo 'Running all tests...'
	@VERBOSE=1 PATH=${PATH} ./run-tests.sh

clean_coverage:
	@rm -f .coverage

flake8:
	@echo 'Running flake8...'
	@flake8 rauth tests

check: flake8 test
	@grep ^TOTAL tests_output/test.log | grep 100% >/dev/null || \
	{ echo 'Unit tests coverage is incomplete.'; exit 1; }
