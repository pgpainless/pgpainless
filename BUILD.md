<!--
SPDX-FileCopyrightText: 2025 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# Build PGPainless

There are a number of different artifacts that can be built from the PGPainless source code:

## `pgpainless-cli/build/libs/pgpainless-cli-X.Y.Z-all.jar`

This is a fat jar, built using the Shadow plugin.
It bundles all necessary dependencies required by the CLI application at runtime.
This artifact will be produced by the `gradle shadowJar` task, which is run as part of the `gradle assemble` task.

## `pgpainless-cli/build/native/nativeCompile/pgpainless-cli`

This is a native image, that can be built using GraalVM which compared to the executable jar file above
offers greatly improved performance by skipping the JVM startup overhead.

To build this image, you need to run `gradle nativeCompile` using a GraalVM-enabled Java SDK.
