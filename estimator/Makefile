SAGE ?= sage
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -c
OUT ?= LoTRS-Estimate-Output-N100T50.generated.txt

.PHONY: all estimate reference test clean

all: estimate

estimate:
	$(SAGE) -c "import lotrs_estimate; lotrs_estimate.main()"

reference:
	$(SAGE) -c "import lotrs_estimate; lotrs_estimate.main()" | tee $(OUT)

test:
	$(SAGE) -c "import unittest, test_alignment; result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromModule(test_alignment)); assert result.wasSuccessful()"

clean:
	$(RM) -f *.pyc *.cprof */*.pyc *.rsp *.log
	$(RM) -rf __pycache__ */__pycache__
