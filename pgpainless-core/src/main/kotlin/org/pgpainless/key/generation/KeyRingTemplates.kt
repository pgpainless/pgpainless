// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.PGPainless.Companion.buildKeyRing
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.key.generation.KeySpec.Companion.getBuilder
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec
import org.pgpainless.util.Passphrase

class KeyRingTemplates(private val version: OpenPGPKeyVersion) {

    /**
     * Generate an RSA OpenPGP key consisting of an RSA primary key used for certification, a
     * dedicated RSA subkey used for signing and a third RSA subkey used for encryption.
     *
     * @param userId userId or null
     * @param length length of the RSA keys
     * @param passphrase passphrase to encrypt the key with. Can be empty for an unencrytped key.
     * @return key
     */
    @JvmOverloads
    fun rsaKeyRing(
        userId: CharSequence?,
        length: RsaLength,
        passphrase: Passphrase = Passphrase.emptyPassphrase()
    ): PGPSecretKeyRing =
        buildKeyRing(version)
            .apply {
                setPrimaryKey(getBuilder(KeyType.RSA(length), KeyFlag.CERTIFY_OTHER))
                addSubkey(getBuilder(KeyType.RSA(length), KeyFlag.SIGN_DATA))
                addSubkey(
                    getBuilder(KeyType.RSA(length), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                setPassphrase(passphrase)
                if (userId != null) {
                    addUserId(userId)
                }
            }
            .build()

    /**
     * Generate an RSA OpenPGP key consisting of an RSA primary key used for certification, a
     * dedicated RSA subkey used for signing and a third RSA subkey used for encryption.
     *
     * @param userId userId or null
     * @param length length of the RSA keys
     * @param password passphrase to encrypt the key with. Can be null or blank for unencrypted
     *   keys.
     * @return key
     */
    fun rsaKeyRing(userId: CharSequence?, length: RsaLength, password: String?): PGPSecretKeyRing =
        password.let {
            if (it.isNullOrBlank()) {
                rsaKeyRing(userId, length, Passphrase.emptyPassphrase())
            } else {
                rsaKeyRing(userId, length, Passphrase.fromPassword(it))
            }
        }

    /**
     * Creates a simple RSA KeyPair of length `length` with user-id `userId`. The KeyPair consists
     * of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     * @param password Password of the key. Can be empty for unencrypted keys.
     * @return [PGPSecretKeyRing] containing the KeyPair.
     */
    @JvmOverloads
    fun simpleRsaKeyRing(
        userId: CharSequence?,
        length: RsaLength,
        passphrase: Passphrase = Passphrase.emptyPassphrase()
    ): PGPSecretKeyRing =
        buildKeyRing(version)
            .apply {
                setPrimaryKey(
                    getBuilder(
                        KeyType.RSA(length),
                        KeyFlag.CERTIFY_OTHER,
                        KeyFlag.SIGN_DATA,
                        KeyFlag.ENCRYPT_COMMS))
                setPassphrase(passphrase)
                if (userId != null) {
                    addUserId(userId.toString())
                }
            }
            .build()

    /**
     * Creates a simple RSA KeyPair of length `length` with user-id `userId`. The KeyPair consists
     * of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     * @param password Password of the key. Can be null or blank for unencrypted keys.
     * @return [PGPSecretKeyRing] containing the KeyPair.
     */
    fun simpleRsaKeyRing(userId: CharSequence?, length: RsaLength, password: String?) =
        password.let {
            if (it.isNullOrBlank()) {
                simpleRsaKeyRing(userId, length, Passphrase.emptyPassphrase())
            } else {
                simpleRsaKeyRing(userId, length, Passphrase.fromPassword(it))
            }
        }

    /**
     * Creates a key ring consisting of an ed25519 EdDSA primary key and a X25519 XDH subkey. The
     * EdDSA primary key is used for signing messages and certifying the sub key. The XDH subkey is
     * used for encryption and decryption of messages.
     *
     * @param userId user-id
     * @param passphrase Password of the private key. Can be empty for an unencrypted key.
     * @return [PGPSecretKeyRing] containing the key pairs.
     */
    @JvmOverloads
    fun simpleEcKeyRing(
        userId: CharSequence?,
        passphrase: Passphrase = Passphrase.emptyPassphrase()
    ): PGPSecretKeyRing {
        val signingKeyType =
            if (version == OpenPGPKeyVersion.v6) KeyType.Ed25519()
            else KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519)
        val encryptionKeyType =
            if (version == OpenPGPKeyVersion.v6) KeyType.X25519()
            else KeyType.XDH_LEGACY(XDHLegacySpec._X25519)
        return buildKeyRing(version)
            .apply {
                setPrimaryKey(getBuilder(signingKeyType, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                addSubkey(
                    getBuilder(encryptionKeyType, KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS))
                setPassphrase(passphrase)
                if (userId != null) {
                    addUserId(userId.toString())
                }
            }
            .build()
    }

    /**
     * Creates a key ring consisting of an ed25519 EdDSA primary key and a X25519 XDH subkey. The
     * EdDSA primary key is used for signing messages and certifying the sub key. The XDH subkey is
     * used for encryption and decryption of messages.
     *
     * @param userId user-id
     * @param passphrase Password of the private key. Can be null or blank for an unencrypted key.
     * @return [PGPSecretKeyRing] containing the key pairs.
     */
    fun simpleEcKeyRing(userId: CharSequence?, password: String?): PGPSecretKeyRing =
        password.let {
            if (it.isNullOrBlank()) {
                simpleEcKeyRing(userId, Passphrase.emptyPassphrase())
            } else {
                simpleEcKeyRing(userId, Passphrase.fromPassword(it))
            }
        }

    /**
     * Generate a modern PGP key ring consisting of an ed25519 EdDSA primary key which is used to
     * certify an X25519 XDH encryption subkey and an ed25519 EdDSA signing key.
     *
     * @param userId primary user id
     * @param passphrase passphrase for the private key. Can be empty for an unencrypted key.
     * @return key ring
     */
    @JvmOverloads
    fun modernKeyRing(
        userId: CharSequence?,
        passphrase: Passphrase = Passphrase.emptyPassphrase()
    ): PGPSecretKeyRing {
        val signingKeyType =
            if (version == OpenPGPKeyVersion.v6) KeyType.Ed25519()
            else KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519)
        val encryptionKeyType =
            if (version == OpenPGPKeyVersion.v6) KeyType.X25519()
            else KeyType.XDH_LEGACY(XDHLegacySpec._X25519)
        return buildKeyRing(version)
            .apply {
                setPrimaryKey(getBuilder(signingKeyType, KeyFlag.CERTIFY_OTHER))
                addSubkey(
                    getBuilder(encryptionKeyType, KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                addSubkey(getBuilder(signingKeyType, KeyFlag.SIGN_DATA))
                setPassphrase(passphrase)
                if (userId != null) {
                    addUserId(userId)
                }
            }
            .build()
    }

    /**
     * Generate a modern PGP key ring consisting of an ed25519 EdDSA primary key which is used to
     * certify an X25519 XDH encryption subkey and an ed25519 EdDSA signing key.
     *
     * @param userId primary user id
     * @param password passphrase for the private key. Can be null or blank for an unencrypted key.
     * @return key ring
     */
    fun modernKeyRing(userId: CharSequence?, password: String?): PGPSecretKeyRing =
        password.let {
            if (it.isNullOrBlank()) {
                modernKeyRing(userId, Passphrase.emptyPassphrase())
            } else {
                modernKeyRing(userId, Passphrase.fromPassword(it))
            }
        }
}
