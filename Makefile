.PHONY: all test clean_coverage clean pep8 pyflakes check 

all:
	@echo 'test           run the unit tests'
	@echo 'coverage       generate coverage statistics'
	@echo 'pep8           check pep8 compliance'
	@echo 'pyflakes       check for unused imports (requires pyflakes)'
	@echo 'check          make sure you are ready to commit'
	@echo 'clean          cleanup the source tree'

test: clean_coverage
	@echo 'Running all tests...'
	@VERBOSE=1 PATH=${PATH} ./run-tests.sh

clean_coverage:
	@rm -f .coverage

pep8:
	@echo 'Checking pep8 compliance...'
	@pep8 rauth tests

pyflakes:
	@echo 'Running pyflakes...'
	@pyflakes rauth tests

check: pep8 pyflakes test
	@grep ^TOTAL tests_output/test.log | grep 100% >/dev/null || \
	{ echo 'Unit tests coverage is incomplete.'; exit 1; }
