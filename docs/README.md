# User Guide for PGPainless

## Build the Guide

```shell
$ make {html|epub|latexpdf}
```

Note: Building requires `mermaid-cli` to be installed in this directory:
```shell
$ # Move here
$ cd pgpainless/docs
$ npm install @mermaid-js/mermaid-cli
```

TODO: This is ugly. Install mermaid-cli globally? Perhaps point to user-installed mermaid-cli in conf.py's mermaid_cmd