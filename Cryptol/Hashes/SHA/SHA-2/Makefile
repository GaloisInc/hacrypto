.PHONY: all

all: SHA-2.pdf

SHA-2.pdf: SHA-2.md
	pandoc -f markdown+raw_tex -t latex --latex-engine=xelatex -o SHA-2.pdf SHA-2.md
