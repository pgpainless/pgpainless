PGPainless - Painless OpenPGP
=============================

**OpenPGP** (`RFC 4480 <https://datatracker.ietf.org/doc/rfc4880/>`_) is an Internet Standard mostly used for email encryption.
It provides mechanisms to ensure *confidentiality*, *integrity* and *authenticity* of messages.
However, OpenPGP can also be used for other purposes, such as secure messaging or as a signature mechanism for software distribution.

**PGPainless** strives to improve the (currently pretty dire) state of the ecosystem of Java libraries and tooling for OpenPGP.

The library focuses on being easy and intuitive to use without getting into your way.
Common functions such as creating keys, encrypting data, and so on are implemented using a builder structure that guides you through the necessary steps.

Internally, it is based on `Bouncy Castles <https://www.bouncycastle.org/java.html>`_ mighty, but low-level OpenPGP API.
PGPainless' goal is to empower you to use OpenPGP without needing to write all the boilerplate code required by Bouncy Castle.
It aims to be secure by default while allowing customization if required.


Contents
--------

.. toctree::

   ecosystem.md
   quickstart.md
   pgpainless-cli/usage.md
   sop.md
   pgpainless-core/indepth.rst