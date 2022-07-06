import os
# Configuration file for the Sphinx documentation builder.

# -- Project information

project = 'PGPainless'
copyright = '2022, Paul Schaub'
author = 'Paul Schaub'

# https://protips.readthedocs.io/git-tag-version.html
latest_tag = os.popen('git describe --abbrev=0').read().strip()
release = latest_tag
version = release

myst_substitutions = {
  "repo_host" : "codeberg.org"
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

# -- Options for EPUB output
#epub_show_urls = 'footnote'

mermaid_cmd = "./node_modules/.bin/mmdc"
mermaid_output_format = 'png'
mermaid_params = ['--theme', 'default', '--width', '800', '--backgroundColor', 'transparent']
