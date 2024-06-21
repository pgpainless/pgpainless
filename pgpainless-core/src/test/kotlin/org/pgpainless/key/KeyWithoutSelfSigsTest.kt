// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import java.io.ByteArrayOutputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.util.io.Streams
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec
import org.pgpainless.key.protection.SecretKeyRingProtector

class KeyWithoutSelfSigsTest {

    @Test
    fun signAndVerify() {
        val key = PGPainless.readKeyRing().secretKeyRing(KEY)
        val cert = PGPainless.extractCertificate(key!!)

        val ciphertextOut = ByteArrayOutputStream()
        val encryptionStream =
            PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertextOut)
                .withOptions(
                    ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptCommunications().addRecipient(cert),
                        SigningOptions.get()
                            .addSignature(SecretKeyRingProtector.unprotectedKeys(), key)))
        encryptionStream.write("Hello, World!\n".toByteArray())
        encryptionStream.close()

        val plaintextOut = ByteArrayOutputStream()
        val decryptionStream =
            PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextOut.toByteArray().inputStream())
                .withOptions(
                    ConsumerOptions.get()
                        .addVerificationCert(cert)
                        .addDecryptionKey(key, SecretKeyRingProtector.unprotectedKeys()))
        Streams.pipeAll(decryptionStream, plaintextOut)
        decryptionStream.close()
    }

    fun generateKey() {
        val key =
            PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519)))
                .addSubkey(
                    KeySpec.getBuilder(
                        KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(
                    KeySpec.getBuilder(
                        KeyType.XDH_LEGACY(XDHLegacySpec._X25519),
                        KeyFlag.ENCRYPT_STORAGE,
                        KeyFlag.ENCRYPT_COMMS))
                .build()
                .let {
                    var cert = PGPainless.extractCertificate(it)
                    cert =
                        PGPPublicKeyRing(
                            buildList {
                                val iterator = cert.publicKeys
                                val primaryKey = iterator.next()
                                add(
                                    PGPPublicKey.removeCertification(
                                        primaryKey, primaryKey.signatures.next()))
                                while (iterator.hasNext()) {
                                    add(iterator.next())
                                }
                            })
                    PGPSecretKeyRing.replacePublicKeys(it, cert)
                }
        println(PGPainless.asciiArmor(key))
    }

    companion object {

        const val KEY =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: DA3E CC77 1CD6 46F0 C6C4  4FDA 86A3 7B22 7802 2FC7\n" +
                "\n" +
                "lFgEZUuWuhYJKwYBBAHaRw8BAQdAuXfarON/+UG1qwhVy4/VCYuEb9iLFLb8KGQt\n" +
                "KfX4Se0AAQDgqGHsb2M43F+6wK5Hla+oZzFkTUsBx8HMpRx2yeQT6hFAnFgEZUuW\n" +
                "uhYJKwYBBAHaRw8BAQdAx0OHISLtekltdUVGGrG/Gs3asc/jG/nqCkBEZ5uyELwA\n" +
                "AP0faf8bprP3fj248/NacfynKEVnjzc1gocfhGiWrnVgAxC1iNUEGBYKAH0FAmVL\n" +
                "lroCngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJlS5a6AAoJED9gFx9r\n" +
                "B25syqoA/0JR3Zcs6fHQ0jW7+u6330SD5h8WvG78IKsE6AfChBLXAP4hlXGidztq\n" +
                "5sOHEQvXD2KPCHEJ6MuQ+rbNSSf0fQhgDwAKCRCGo3sieAIvxzmIAP9+9vRoevUM\n" +
                "luQhZzQ7DgYqTCyNkeq2cpVgOfa0lyVDgwEApwrd5DlU3GorGHAQHFS6jhw1IOoG\n" +
                "FGQ3zpWaOXd7XwKcXQRlS5a6EgorBgEEAZdVAQUBAQdAZIY7ISyNzp0oMoK0dgb8\n" +
                "dX6t/i4Uh+l0jnxM0Z1dEB8DAQgHAAD/fhL5dzdJQ7hFhr78AmDEZKFE4txZFPvd\n" +
                "ZVFvIWTthFgQ5Ih1BBgWCgAdBQJlS5a6Ap4BApsMBRYCAwEABAsJCAcFFQoJCAsA\n" +
                "CgkQhqN7IngCL8cIGgEAzydjTfKvdrTvzXXu97j8TAoOxk89QnLqsM6BU0VsVmkA\n" +
                "/1IzH+PXgPPW9ff+elxTi2NWmK+P033P6i5b5Jdf41YD\n" +
                "=GBVS\n" +
                "-----END PGP PRIVATE KEY BLOCK-----"
    }
}
