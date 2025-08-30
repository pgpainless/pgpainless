// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception

import java.lang.AssertionError

/**
 * This exception gets thrown, when the integrity of an OpenPGP key is broken. That could happen on
 * accident, or during an active attack, so take this exception seriously.
 */
class KeyIntegrityException : AssertionError("Key Integrity Exception")
