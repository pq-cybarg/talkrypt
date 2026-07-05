# Machine-checked formal verification of talkrypt's group-message authentication.
# Requires F* on PATH (github.com/FStarLang/FStar). Run: `make verify`.
FSTAR ?= fstar.exe

.PHONY: verify clean
verify:
	$(FSTAR) GroupAuth.fst

clean:
	rm -f *.checked *.krml
