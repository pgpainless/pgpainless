// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.KeySpecBuilder;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.Passphrase;

/**
 * This class demonstrates how to use PGPainless to generate secret keys.
 * In general the starting point for generating secret keys using PGPainless is {@link PGPainless#generateKeyRing()}.
 * The result ({@link org.pgpainless.key.generation.KeyRingBuilder}) provides some factory methods for key archetypes
 * such as {@link org.pgpainless.key.generation.KeyRingTemplates#modernKeyRing(CharSequence, String)} or
 * {@link org.pgpainless.key.generation.KeyRingTemplates#simpleRsaKeyRing(CharSequence, RsaLength)}.
 *
 * Those methods always take a user-id which is used as primary user-id, as well as a passphrase which is used to encrypt
 * the secret key.
 * To generate unencrypted secret keys, just pass {@code null} as passphrase.
 *
 * Besides the archetype methods, it is possible to generate fully customized keys (see {@link #generateCustomOpenPGPKey()}).
 */
public class GenerateKeys {

    /**
     * This example demonstrates how to generate a modern OpenPGP key which consists of an ed25519 EdDSA primary key
     * used solely for certification of subkeys, as well as an ed25519 EdDSA signing subkey, and an X25519 ECDH
     * encryption subkey.
     *
     * This is the recommended way to generate OpenPGP keys with PGPainless.
     */
    @Test
    public void generateModernEcKey()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        // Define a primary user-id
        String userId = "gbaker@pgpainless.org";
        // Set a password to protect the secret key
        String password = "ra1nb0w";
        // Generate the OpenPGP key
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing(userId, password);
        // Extract public key
        PGPPublicKeyRing publicKey = PGPainless.extractCertificate(secretKey);
        // Encode the public key to an ASCII armored string ready for sharing
        String asciiArmoredPublicKey = PGPainless.asciiArmor(publicKey);
        assertTrue(asciiArmoredPublicKey.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        KeyRingInfo keyInfo = new KeyRingInfo(secretKey);
        assertEquals(3, keyInfo.getSecretKeys().size());
        assertEquals(userId, keyInfo.getPrimaryUserId());
        assertEquals(PublicKeyAlgorithm.EDDSA.getAlgorithmId(),
                keyInfo.getPublicKey().getAlgorithm());
        assertEquals(PublicKeyAlgorithm.EDDSA.getAlgorithmId(),
                keyInfo.getSigningSubkeys().get(0).getAlgorithm());
        assertEquals(PublicKeyAlgorithm.ECDH.getAlgorithmId(),
                keyInfo.getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getAlgorithm());
    }

    /**
     * This example demonstrates how to generate a simple OpenPGP key consisting of a 4096-bit RSA key.
     * The RSA key is used for both signing and certifying, as well as encryption.
     *
     * This method is recommended if the application has to deal with legacy clients with poor algorithm support.
     */
    @Test
    public void generateSimpleRSAKey()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        // Define a primary user-id
        String userId = "mpage@pgpainless.org";
        // Set a password to protect the secret key
        String password = "b1angl3s";
        // Generate the OpenPGP key
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .simpleRsaKeyRing(userId, RsaLength._4096, password);

        KeyRingInfo keyInfo = new KeyRingInfo(secretKey);
        assertEquals(1, keyInfo.getSecretKeys().size());
        assertEquals(userId, keyInfo.getPrimaryUserId());
        assertEquals(PublicKeyAlgorithm.RSA_GENERAL.getAlgorithmId(), keyInfo.getPublicKey().getAlgorithm());
    }

    /**
     * This example demonstrates how to generate a simple OpenPGP key based on elliptic curves.
     * The key consists of an ECDSA primary key that is used both for certification of subkeys, and signing of data,
     * and a single ECDH encryption subkey.
     *
     * This method is recommended if small keys and high performance are desired.
     */
    @Test
    public void generateSimpleECKey()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        // Define a primary user-id
        String userId = "mhelms@pgpainless.org";
        // Set a password to protect the secret key
        String password = "tr4ns";
        // Generate the OpenPGP key
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .simpleEcKeyRing(userId, password);


        KeyRingInfo keyInfo = new KeyRingInfo(secretKey);
        assertEquals(2, keyInfo.getSecretKeys().size());
        assertEquals(userId, keyInfo.getPrimaryUserId());
    }

    /**
     * This example demonstrates how to generate a custom OpenPGP secret key.
     * Among user-id and password, the user can add an arbitrary number of subkeys and specify their algorithms and
     * algorithm preferences.
     *
     * If the target key amalgamation (key ring) should consist of more than just a single (sub-)key, start by providing
     * the primary key specification using {@link org.pgpainless.key.generation.KeyRingBuilder#setPrimaryKey(KeySpec)}.
     * Any additional subkeys can be then added using {@link org.pgpainless.key.generation.KeyRingBuilder#addSubkey(KeySpec)}.
     *
     * {@link KeySpec} objects can best be obtained by using the {@link KeySpec#getBuilder(KeyType, KeyFlag, KeyFlag...)}
     * method and providing a {@link KeyType}.
     * There are a bunch of factory methods for different {@link KeyType} implementations present in {@link KeyType} itself
     * (such as {@link KeyType#ECDH(EllipticCurve)}). {@link KeyFlag KeyFlags} determine
     * the use of the key, like encryption, signing data or certifying subkeys.
     *
     * If you so desire, you can now specify your own algorithm preferences.
     * For that, see {@link org.pgpainless.key.generation.KeySpecBuilder#overridePreferredCompressionAlgorithms(CompressionAlgorithm...)},
     * {@link org.pgpainless.key.generation.KeySpecBuilder#overridePreferredHashAlgorithms(HashAlgorithm...)} or
     * {@link org.pgpainless.key.generation.KeySpecBuilder#overridePreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm...)}.
     *
     * Note, that if you set preferred algorithms, the preference lists are sorted from high priority to low priority.
     *
     * When setting the primary key spec ({@link org.pgpainless.key.generation.KeyRingBuilder#setPrimaryKey(KeySpecBuilder)}),
     * make sure that the primary key spec has the {@link KeyFlag} {@link KeyFlag#CERTIFY_OTHER} set, as this is a requirement
     * for primary keys.
     *
     * Furthermore, you have to set at least the primary user-id via
     * {@link org.pgpainless.key.generation.KeyRingBuilder#addUserId(String)},
     * but you can also add additional user-ids.
     *
     * If you want the key to expire at a certain point in time, call
     * {@link org.pgpainless.key.generation.KeyRingBuilder#setExpirationDate(Date)}.
     * Lastly you can decide whether to set a passphrase to protect the secret key using
     * {@link org.pgpainless.key.generation.KeyRingBuilder#setPassphrase(Passphrase)}.
     */
    @Test
    public void generateCustomOpenPGPKey()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        // Instead of providing a string, we can assemble a user-id by using the user-id builder.
        // The example below corresponds to "Morgan Carpenter (Pride!) <mcarpenter@pgpainless.org>"
        UserId userId = UserId.newBuilder()
                .withName("Morgan Carpenter")
                .withEmail("mcarpenter@pgpainless.org")
                .withComment("Pride!")
                .build();
        String additionalUserId = "mcarpenter@christopher.street";

        // It is recommended to use the Passphrase class, as it can be used to safely invalidate passwords from memory
        Passphrase passphrase = Passphrase.fromPassword("1nters3x");

        PGPSecretKeyRing secretKey = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519),
                        // The primary key MUST carry the CERTIFY_OTHER flag, but CAN carry additional flags
                        KeyFlag.CERTIFY_OTHER))
                // Add the first subkey (in this case encryption)
                .addSubkey(KeySpec.getBuilder(
                                // We choose an ECDH key over the brainpoolp256r1 curve
                                KeyType.ECDH(EllipticCurve._BRAINPOOLP256R1),
                                // Our key can encrypt both communication data, and data at rest
                                KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS
                        )
                        // Optionally: Configure the subkey with custom algorithm preferences
                        //  It is recommended though to go with PGPainless' defaults which can be found in the
                        //  AlgorithmSuite class.
                        .overridePreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_128)
                        .overridePreferredHashAlgorithms(HashAlgorithm.SHA512, HashAlgorithm.SHA384, HashAlgorithm.SHA256)
                        .overridePreferredCompressionAlgorithms(CompressionAlgorithm.ZIP, CompressionAlgorithm.BZIP2, CompressionAlgorithm.ZLIB)
                        .build())
                // Add the second subkey (signing)
                .addSubkey(KeySpec.getBuilder(
                        KeyType.ECDSA(EllipticCurve._BRAINPOOLP384R1),
                        // This key is used for creating signatures only
                        KeyFlag.SIGN_DATA
                ))
                // Set primary user-id
                .addUserId(userId)
                // Add an additional user id. This step can be repeated
                .addUserId(additionalUserId)
                // Set passphrase. Alternatively use .withoutPassphrase() to leave key unprotected.
                .setPassphrase(passphrase)
                .build();


        KeyRingInfo keyInfo = new KeyRingInfo(secretKey);
        assertEquals(3, keyInfo.getSecretKeys().size());
        assertEquals("Morgan Carpenter (Pride!) <mcarpenter@pgpainless.org>", keyInfo.getPrimaryUserId());
        assertTrue(keyInfo.isUserIdValid(additionalUserId));
    }

}
