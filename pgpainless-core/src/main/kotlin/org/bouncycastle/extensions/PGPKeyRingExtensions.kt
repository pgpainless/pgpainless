// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import org.bouncycastle.openpgp.PGPKeyRing
import org.pgpainless.key.SubkeyIdentifier

/**
 * Return true, if this [PGPKeyRing] contains the subkey identified by the [SubkeyIdentifier].
 */
fun PGPKeyRing.matches(subkeyIdentifier: SubkeyIdentifier): Boolean =
        this.publicKey.keyID == subkeyIdentifier.primaryKeyId &&
                this.getPublicKey(subkeyIdentifier.subkeyId) != null