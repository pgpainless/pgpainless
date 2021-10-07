// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

public interface Version {

    /**
     * Return the implementations name.
     *
     * @return implementation name
     */
    String getName();

    /**
     * Return the implementations version string.
     *
     * @return version string
     */
    String getVersion();
}
