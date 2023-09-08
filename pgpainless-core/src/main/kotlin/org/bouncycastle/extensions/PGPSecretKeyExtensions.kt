// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.PGPSecretKey

/**
 * Returns indication that the secret key is encrypted.
 *
 * @return true if secret key is encrypted, false otherwise.
 */
fun PGPSecretKey?.isEncrypted(): Boolean = (this != null) && (s2KUsage != 0)

/**
 * Returns indication that the secret key is not encrypted.
 *
 * @return true if secret key is encrypted, false otherwise.
 */
fun PGPSecretKey?.isDecrypted(): Boolean = (this == null) || (s2KUsage == 0)

/**
 * Returns indication that the secret key has S2K of a type GNU_DUMMY_S2K.
 *
 * @return true if secret key has S2K of type GNU_DUMMY_S2K, false otherwise.
 */
fun PGPSecretKey?.hasDummyS2K(): Boolean = (this != null) && (s2K?.type == S2K.GNU_DUMMY_S2K)
