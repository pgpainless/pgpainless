<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->

# Evaluate Regular Expressions in OpenPGP Signatures using TCL-Regex

RFC4880 specifies contains a section about RegularExpression subpackets on signatures.
Within this section, the syntax of the RegularExpression subpackets is defined to be the same as Henry Spencer's "almost public domain" regular expression package.

Since Java's `java.util.regex` syntax is too powerful, this module exists to implement regex evaluation using [tcl-regex](https://github.com/basis-technology-corp/tcl-regex-java)
which appears to be a Java port of Henry Spencers regex package.

To make use of this implementation, simply call
```java
RegexInterpreterFactory.setInstance(new HSRegexInterpreterFactory());
```
