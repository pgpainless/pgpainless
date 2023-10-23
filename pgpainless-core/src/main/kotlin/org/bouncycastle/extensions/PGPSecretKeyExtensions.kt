// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle.extensions

import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.exception.KeyIntegrityException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.protection.UnlockSecretKey
import org.pgpainless.util.Passphrase

/**
 * Unlock the secret key to get its [PGPPrivateKey].
 *
 * @param passphrase passphrase to unlock the secret key with.
 * @throws PGPException if the key cannot be unlocked
 * @throws KeyIntegrityException if the public key part was tampered with
 * @throws WrongPassphraseException
 */
@Throws(PGPException::class, KeyIntegrityException::class)
fun PGPSecretKey.unlock(passphrase: Passphrase): PGPPrivateKey =
    UnlockSecretKey.unlockSecretKey(this, passphrase)

/**
 * Unlock the secret key to get its [PGPPrivateKey].
 *
 * @param protector protector to unlock the secret key.
 * @throws PGPException if the key cannot be unlocked
 * @throws KeyIntegrityException if the public key part was tampered with
 */
@Throws(PGPException::class, KeyIntegrityException::class)
@JvmOverloads
fun PGPSecretKey.unlock(
    protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
): PGPPrivateKey = UnlockSecretKey.unlockSecretKey(this, protector)

/**
 * Unlock the secret key to get its [PGPPrivateKey].
 *
 * @param decryptor decryptor to unlock the secret key.
 * @throws PGPException if the key cannot be unlocked
 * @throws KeyIntegrityException if the public key part was tampered with
 */
@Throws(PGPException::class, KeyIntegrityException::class)
fun PGPSecretKey.unlock(decryptor: PBESecretKeyDecryptor?): PGPPrivateKey =
    UnlockSecretKey.unlockSecretKey(this, decryptor)

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

/** Return the [PublicKeyAlgorithm] of this key. */
val PGPSecretKey.publicKeyAlgorithm: PublicKeyAlgorithm
    get() = publicKey.publicKeyAlgorithm

/** Return the [OpenPgpFingerprint] of this key. */
val PGPSecretKey.openPgpFingerprint: OpenPgpFingerprint
    get() = OpenPgpFingerprint.of(this)
