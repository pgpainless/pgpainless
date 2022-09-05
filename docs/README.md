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

Note: Diagrams are currently not built from source.
Instead, pre-built image files are used directly, because there are issues with mermaid in CLI systems.

If you want to build the diagrams from source, you need `mermaid-cli` to be installed on your system.
```shell
$ npm install -g @mermaid-js/mermaid-cli
```

You can then use `mmdc` to build/update single diagram files like this:
```shell
mmdc --theme default --width 1600 --backgroundColor transparent -i ecosystem_dia.md -o ecosystem_dia.svg
```
