% ndss.cls — Minimal NDSS 2027 document class
% Based on the official NDSS template (US Letter, two-column, 10pt)
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{ndss}[2026/05/23 NDSS 2027 Paper Format]

\LoadClass[10pt,twocolumn,letterpaper]{article}

\RequirePackage[margin=1in]{geometry}
\RequirePackage{times}
\RequirePackage{xspace}
\RequirePackage{hyperref}
\RequirePackage{graphicx}
\RequirePackage{booktabs}
\RequirePackage{amsmath}
\RequirePackage{enumitem}

% Title formatting
\renewcommand{\maketitle}{%
  \twocolumn[%
    \begin{center}
      {\Large\bfseries \@title \par}
      \vspace{1em}
      {\large \@author \par}
      \vspace{1.5em}
    \end{center}
  ]%
}

% Section formatting
\renewcommand{\section}{\@startsection{section}{1}{\z@}%
  {-3.5ex plus -1ex minus -.2ex}{2.3ex plus .2ex}%
  {\normalfont\large\bfseries}}
\renewcommand{\subsection}{\@startsection{subsection}{2}{\z@}%
  {-3.25ex plus -1ex minus -.2ex}{1.5ex plus .2ex}%
  {\normalfont\normalsize\bfseries}}

% Abstract
\renewenvironment{abstract}{%
  \begin{center}\textbf{Abstract}\end{center}
  \begin{quote}\small
}{%
  \end{quote}
}

\endinput
