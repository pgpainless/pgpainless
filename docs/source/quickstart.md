# Quickstart Guide

In this guide, we will get you started with OpenPGP using PGPainless as quickly as possible.

At first though, you need to decide which API you want to use;

* PGPainless' core API is powerful and heavily customizable
* The SOP API is a bit less powerful, but *dead* simple to use

The SOP API is the recommended way to go if you just want to get started already.

In case you need more technical documentation, Javadoc can be found in the following places:
* For the core API: {{ '[pgpainless-core](https://javadoc.io/doc/org.pgpainless/pgpainless-core/{}/index.html)'.format(env.config.version) }}
* For the SOP API: {{ '[pgpainless-sop](https://javadoc.io/doc/org.pgpainless/pgpainless-sop/{}/index.html)'.format(env.config.version) }}

```{include} pgpainless-sop/quickstart.md
```

```{include} pgpainless-core/quickstart.md
```