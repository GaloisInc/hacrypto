all:	readme.pdf
	cd aes && $(MAKE)

readme.pdf: readme.md
	pandoc -f markdown -t latex -o readme.pdf readme.md

