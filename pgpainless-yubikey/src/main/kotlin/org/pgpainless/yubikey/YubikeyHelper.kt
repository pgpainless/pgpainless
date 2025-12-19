// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.openpgp.KeyRef
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey
import org.gnupg.GnuPGDummyKeyUtil
import org.pgpainless.PGPainless
import org.pgpainless.bouncycastle.extensions.toOpenPGPKey
import org.pgpainless.exception.KeyException
import org.pgpainless.key.OpenPgpFingerprint

class YubikeyHelper(private val api: PGPainless = PGPainless.getInstance()) {

    fun moveToYubikey(
        componentKey: OpenPGPPrivateKey,
        yubikey: Yubikey,
        adminPin: CharArray,
        keyRef: KeyRef = guessKeyRefForKey(componentKey.publicKey)
    ): OpenPGPKey {
        // Move private key to hardware token
        yubikey.storeKeyInSlot(componentKey, keyRef, adminPin)

        // Modify software key to indicate key has been diverted to card
        return indicateMovedToCard(componentKey.secretKey, yubikey)
    }

    private fun indicateMovedToCard(key: OpenPGPSecretKey, yubikey: Yubikey): OpenPGPKey {
        return GnuPGDummyKeyUtil.modify(key.openPGPKey)
            .divertPrivateKeysToCard(
                { it.matchesExplicit(key.keyIdentifier) },
                GnuPGDummyKeyUtil.serialToBytes(yubikey.info.serialNumber!!))
            .toOpenPGPKey(api.implementation)
    }

    private fun guessKeyRefForKey(key: OpenPGPComponentKey): KeyRef {
        return when {
            key.isSigningKey -> KeyRef.SIG
            key.isEncryptionKey -> KeyRef.DEC
            key.isCertificationKey -> KeyRef.ATT
            else ->
                throw KeyException.GeneralKeyException(
                    "Cannot determine usage for the key.", OpenPgpFingerprint.of(key))
        }
    }
}
