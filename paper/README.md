# Paper: kcov-dataflow

## Prerequisites

```bash
# Debian/Ubuntu
sudo apt install texlive-base texlive-latex-recommended texlive-latex-extra \
  texlive-fonts-recommended texlive-science zip

# Or full TeX Live (simpler)
sudo apt install texlive-full
```

Required packages: `pdflatex`, `bibtex`, `zip`.

## Build

```bash
./tex.sh
```

Outputs:
- `arxiv/main.pdf` -- compiled paper
- `arxiv.zip` -- flat archive ready for arXiv submission

## Structure

```
paper/
├── tex.sh              Build script (PDF + arxiv.zip)
├── Makefile            Alternative: `make` uses latexmk
├── arxiv/
│   ├── main.tex        Main paper (PRIMEarxiv format)
│   └── PRIMEarxiv.sty  Style file
├── shared/
│   ├── macros.tex      Shared macros (\toolname, etc.)
│   └── references.bib  Bibliography
└── overleaf/           IEEEtran version (for Overleaf)
    ├── main.tex
    ├── main.bib
    ├── utils/command.tex
    └── sections/*.tex
```

## Overleaf

Upload the entire `overleaf/` directory to Overleaf. It compiles standalone with IEEEtran (no extra packages needed beyond a standard Overleaf project).
