#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/arxiv"

echo "=== Building PDF ==="
pdflatex -interaction=nonstopmode main.tex > /dev/null
bibtex main > /dev/null 2>&1 || true
pdflatex -interaction=nonstopmode main.tex > /dev/null
pdflatex -interaction=nonstopmode main.tex > /dev/null
echo "PDF: $(pwd)/main.pdf ($(du -h main.pdf | cut -f1))"

echo "=== Preparing arxiv.zip ==="
TMPDIR=$(mktemp -d)
# Main tex (flatten macros input path)
sed 's|\\input{../shared/macros}|\\input{macros}|' main.tex > "$TMPDIR/main.tex"
# Shared files
cp ../shared/macros.tex "$TMPDIR/"
cp ../shared/references.bib "$TMPDIR/"
# Style
cp PRIMEarxiv.sty "$TMPDIR/"
# Pre-compiled bibliography (arxiv needs .bbl)
cp main.bbl "$TMPDIR/"
# Media if any
[ -d media ] && cp -r media "$TMPDIR/"

cd "$TMPDIR"
zip -r arxiv.zip . > /dev/null
mv arxiv.zip "$SCRIPT_DIR/arxiv.zip"
rm -rf "$TMPDIR"

echo "ZIP: $SCRIPT_DIR/arxiv.zip"
echo "Done."
