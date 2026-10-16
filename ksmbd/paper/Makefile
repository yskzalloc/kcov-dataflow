.PHONY: all arxiv view clean zip

all: arxiv

arxiv:
	cd arxiv && latexmk -pdf -interaction=nonstopmode main.tex

view:
	cd arxiv && latexmk -pdf -pvc main.tex

zip: arxiv
	./tex.sh

clean:
	cd arxiv && latexmk -C 2>/dev/null; true
