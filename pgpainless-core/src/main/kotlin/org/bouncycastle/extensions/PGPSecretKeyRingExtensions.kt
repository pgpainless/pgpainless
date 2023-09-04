// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing

val PGPSecretKeyRing.certificate: PGPPublicKeyRing
    get() = PGPPublicKeyRing(this.publicKeys.asSequence().toList())