# User Guide for PGPainless

Documentation for PGPainless is built from Markdown using Sphinx and MyST.

A built version of the documentation is available on http://pgpainless.rtfd.io/

## Useful resources

* [Sphix Documentation Generator](https://www.sphinx-doc.org/en/master/)
* [MyST Markdown Syntax](https://myst-parser.readthedocs.io/en/latest/index.html)

## Build the Guide

To build:

```shell
$ make {html|epub|latexpdf}
```

Note: Building diagrams from source requires `mermaid-cli` to be installed.
```shell
$ npm install -g @mermaid-js/mermaid-cli
```
