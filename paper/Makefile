.PHONY: all clean

all: paper.pdf

paper.pdf: paper.tex
	latexmk -pdf paper.tex

clean:
	latexmk -C
	rm -f *.bbl *.run.xml *-blx.bib *.synctex.gz
