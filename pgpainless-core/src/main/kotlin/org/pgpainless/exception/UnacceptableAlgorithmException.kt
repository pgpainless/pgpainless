// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception

import org.bouncycastle.openpgp.PGPException

/** Exception that gets thrown if unacceptable algorithms are encountered. */
class UnacceptableAlgorithmException(message: String) : PGPException(message)
