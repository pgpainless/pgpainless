// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

public interface Version {

    /**
     * Return the implementations name.
     * e.g. "SOP",
     *
     * @return implementation name
     */
    String getName();

    /**
     * Return the implementations short version string.
     * e.g. "1.0"
     *
     * @return version string
     */
    String getVersion();

    /**
     * Return version information about the used OpenPGP backend.
     * e.g. "Bouncycastle 1.70"
     *
     * @return backend version string
     */
    String getBackendVersion();

    /**
     * Return an extended version string containing multiple lines of version information.
     * The first line MUST match the information produced by {@link #getName()} and {@link #getVersion()}, but the rest of the text
     * has no defined structure.
     * Example:
     * <pre>
     *     "SOP 1.0
     *     Awesome PGP!
     *     Using Bouncycastle 1.70
     *     LibFoo 1.2.2
     *     See https://pgp.example.org/sop/ for more information"
     * </pre>
     *
     * @return extended version string
     */
    String getExtendedVersion();
}
