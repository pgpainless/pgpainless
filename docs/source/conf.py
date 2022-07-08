import os
# Configuration file for the Sphinx documentation builder.

# -- Project information

project = 'PGPainless'
copyright = '2022, Paul Schaub'
author = 'Paul Schaub'

master_doc = 'index'

# https://protips.readthedocs.io/git-tag-version.html
latest_tag = os.popen('git describe --abbrev=0').read().strip()
release = latest_tag
version = release

myst_substitutions = {
  "repo_host" : "codeberg.org", # or 'github.com'
#  "repo_host" : "github.com",
  "repo_pgpainless_src" : "codeberg.org/pgpainless/pgpainless/src/branch",
#  "repo_pgpainless_src" : "github.com/pgpainless/pgpainless/tree",
}

# -- General configuration

extensions = [
    'myst_parser',
    'sphinxcontrib.mermaid',
    'sphinx.ext.duration',
    'sphinx.ext.doctest',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
]

source_suffix = ['.rst', '.md']

myst_enable_extensions = [
    'colon_fence',
    'substitution',
]

myst_heading_anchors = 3

templates_path = ['_templates']

# -- Options for HTML output

html_theme = 'sphinx_rtd_theme'

# Show URLs as footnotes
#epub_show_urls = 'footnote'
latex_show_urls = 'footnote'

# 'raw' does not work for epub and pdf, neither does 'svg'
mermaid_output_format = 'png'
mermaid_params = ['--theme', 'default', '--width', '1600', '--backgroundColor', 'transparent']
