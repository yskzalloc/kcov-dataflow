.PHONY: all arxiv ndss view-arxiv view-ndss clean

all: arxiv ndss

arxiv:
	cd arxiv && latexmk -pdf -interaction=nonstopmode main.tex

ndss:
	cd ndss && latexmk -pdf -interaction=nonstopmode main.tex

# Live-preview (auto-recompile on save, opens PDF viewer)
view-arxiv:
	cd arxiv && latexmk -pdf -pvc main.tex

view-ndss:
	cd ndss && latexmk -pdf -pvc main.tex

clean:
	cd arxiv && latexmk -C 2>/dev/null; true
	cd ndss && latexmk -C 2>/dev/null; true
