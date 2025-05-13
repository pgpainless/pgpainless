// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.OutputStream
import java.lang.RuntimeException
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import org.bouncycastle.bcpg.PacketFormat
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.key.generation.KeyRingBuilder
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec
import org.pgpainless.util.Passphrase
import sop.Profile
import sop.Ready
import sop.exception.SOPGPException
import sop.operation.GenerateKey

/** Implementation of the `generate-key` operation using PGPainless. */
class GenerateKeyImpl(private val api: PGPainless) : GenerateKey {

    companion object {
        @JvmField
        val CURVE25519_PROFILE =
            Profile(
                "draft-koch-eddsa-for-openpgp-00", "Generate EdDSA / ECDH keys using Curve25519")
        @JvmField val RSA4096_PROFILE = Profile("rfc4880", "Generate 4096-bit RSA keys")

        @JvmField val SUPPORTED_PROFILES = listOf(CURVE25519_PROFILE, RSA4096_PROFILE)
    }

    private val userIds = mutableSetOf<String>()
    private var armor = true
    private var signingOnly = false
    private var passphrase = Passphrase.emptyPassphrase()
    private var profile = CURVE25519_PROFILE.name

    override fun generate(): Ready {
        try {
            val key = generateKeyWithProfile(profile, userIds, passphrase, signingOnly)
            return object : Ready() {
                override fun writeTo(outputStream: OutputStream) {
                    if (armor) {
                        val armored = key.toAsciiArmoredString(PacketFormat.CURRENT)
                        outputStream.write(armored.toByteArray())
                    } else {
                        outputStream.write(key.getEncoded(PacketFormat.CURRENT))
                    }
                }
            }
        } catch (e: InvalidAlgorithmParameterException) {
            throw SOPGPException.UnsupportedAsymmetricAlgo("Unsupported asymmetric algorithm.", e)
        } catch (e: NoSuchAlgorithmException) {
            throw SOPGPException.UnsupportedAsymmetricAlgo("Unsupported asymmetric algorithm.", e)
        } catch (e: PGPException) {
            throw RuntimeException(e)
        }
    }

    override fun noArmor(): GenerateKey = apply { armor = false }

    override fun profile(profile: String): GenerateKey = apply {
        this.profile =
            SUPPORTED_PROFILES.find { it.name == profile }?.name
                ?: throw SOPGPException.UnsupportedProfile("generate-key", profile)
    }

    override fun signingOnly(): GenerateKey = apply { signingOnly = true }

    override fun userId(userId: String): GenerateKey = apply { userIds.add(userId) }

    override fun withKeyPassword(password: String): GenerateKey = apply {
        this.passphrase = Passphrase.fromPassword(password)
    }

    private fun generateKeyWithProfile(
        profile: String,
        userIds: Set<String>,
        passphrase: Passphrase,
        signingOnly: Boolean
    ): OpenPGPKey {
        val keyBuilder: KeyRingBuilder =
            when (profile) {
                CURVE25519_PROFILE.name ->
                    api.buildKey()
                        .setPrimaryKey(
                            KeySpec.getBuilder(
                                KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519),
                                KeyFlag.CERTIFY_OTHER))
                        .addSubkey(
                            KeySpec.getBuilder(
                                KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA))
                        .apply {
                            if (!signingOnly) {
                                addSubkey(
                                    KeySpec.getBuilder(
                                        KeyType.XDH_LEGACY(XDHLegacySpec._X25519),
                                        KeyFlag.ENCRYPT_COMMS,
                                        KeyFlag.ENCRYPT_STORAGE))
                            }
                        }
                RSA4096_PROFILE.name -> {
                    api.buildKey()
                        .setPrimaryKey(
                            KeySpec.getBuilder(KeyType.RSA(RsaLength._4096), KeyFlag.CERTIFY_OTHER))
                        .addSubkey(
                            KeySpec.getBuilder(KeyType.RSA(RsaLength._4096), KeyFlag.SIGN_DATA))
                        .apply {
                            if (!signingOnly) {
                                addSubkey(
                                    KeySpec.getBuilder(
                                        KeyType.RSA(RsaLength._4096),
                                        KeyFlag.ENCRYPT_COMMS,
                                        KeyFlag.ENCRYPT_STORAGE))
                            }
                        }
                }
                else -> throw SOPGPException.UnsupportedProfile("generate-key", profile)
            }

        userIds.forEach { keyBuilder.addUserId(it) }
        if (!passphrase.isEmpty) {
            keyBuilder.setPassphrase(passphrase)
        }
        return keyBuilder.build()
    }
}
