// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.Passphrase;

/**
 * PGPainless offers a simple API to modify keys by adding and replacing signatures and/or subkeys.
 * The main entry point to this API is {@link PGPainless#modifyKeyRing(PGPSecretKeyRing)}.
 */
public class ModifyKeys {

    private final String userId = "alice@pgpainless.org";
    private final String originalPassphrase = "p4ssw0rd";
    private PGPSecretKeyRing secretKey;
    private long primaryKeyId;
    private KeyIdentifier encryptionSubkeyId;
    private KeyIdentifier signingSubkeyId;

    @BeforeEach
    public void generateKey() {
        secretKey = PGPainless.generateKeyRing()
                .modernKeyRing(userId, originalPassphrase);

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        primaryKeyId = info.getKeyIdentifier().getKeyId();
        encryptionSubkeyId = info.getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getKeyIdentifier();
        signingSubkeyId = info.getSigningSubkeys().get(0).getKeyIdentifier();
    }

    /**
     * This example demonstrates how to extract a certificate (public key) from a secret key.
     */
    @Test
    public void extractPublicKey() {
        // the certificate consists of only the public keys
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);

        KeyRingInfo info = PGPainless.inspectKeyRing(certificate);
        assertFalse(info.isSecretKey());
    }

    /**
     * This example demonstrates how to export a secret key or certificate to an ASCII armored string.
     */
    @Test
    public void toAsciiArmoredString() {
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);

        String asciiArmoredSecretKey = PGPainless.asciiArmor(secretKey);
        String asciiArmoredCertificate = PGPainless.asciiArmor(certificate);

        assertTrue(asciiArmoredSecretKey.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assertTrue(asciiArmoredCertificate.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }

    /**
     * This example demonstrates how to change the passphrase of a secret key and all its subkeys.
     */
    @Test
    public void changePassphrase() throws PGPException {
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword(originalPassphrase))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("n3wP4ssW0rD"))
                .done();

        // Old passphrase no longer works
        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKey.getSecretKey(), Passphrase.fromPassword(originalPassphrase)));
        // But the new one does
        UnlockSecretKey.unlockSecretKey(secretKey.getSecretKey(), Passphrase.fromPassword("n3wP4ssW0rD"));
    }

    /**
     * This example demonstrates how to change the passphrase of a single subkey in a key to a new passphrase.
     * Only the passphrase of the targeted key will be changed. All other keys remain untouched.
     */
    @Test
    public void changeSingleSubkeyPassphrase() throws PGPException {
        secretKey = PGPainless.modifyKeyRing(secretKey)
                // Here we change the passphrase of the encryption subkey
                .changeSubKeyPassphraseFromOldPassphrase(encryptionSubkeyId.getKeyId(), Passphrase.fromPassword(originalPassphrase))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("cryptP4ssphr4s3"))
                .done();

        // encryption key can now only be unlocked using the new passphrase
        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(
                        secretKey.getSecretKey(encryptionSubkeyId), Passphrase.fromPassword(originalPassphrase)));
        UnlockSecretKey.unlockSecretKey(
                secretKey.getSecretKey(encryptionSubkeyId), Passphrase.fromPassword("cryptP4ssphr4s3"));
        // primary key remains unchanged
        UnlockSecretKey.unlockSecretKey(
                secretKey.getSecretKey(primaryKeyId), Passphrase.fromPassword(originalPassphrase));
    }

    /**
     * This example demonstrates how to add an additional user-id to a key.
     */
    @Test
    public void addUserId() throws PGPException {
        SecretKeyRingProtector protector =
                SecretKeyRingProtector.unlockEachKeyWith(Passphrase.fromPassword(originalPassphrase), secretKey);
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .addUserId("additional@user.id", protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        assertTrue(info.isUserIdValid("additional@user.id"));
        assertFalse(info.isUserIdValid("another@user.id"));
    }

    /**
     * This example demonstrates how to add an additional subkey to an existing key.
     * Prerequisites are a {@link SecretKeyRingProtector} that is capable of unlocking the primary key of the existing key,
     * and a {@link Passphrase} for the new subkey.
     * <p>
     * There are two ways to add a subkey into an existing key;
     * Either the subkey gets generated on the fly (see below),
     * or the subkey already exists. In the latter case, the user has to provide
     * {@link org.bouncycastle.openpgp.PGPSignatureSubpacketVector PGPSignatureSubpacketVectors} for the binding signature
     * manually.
     * <p>
     * Once the subkey is added, it can be decrypted using the provided subkey passphrase.
     */
    @Test
    public void addSubkey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        // Protector for unlocking the existing secret key
        SecretKeyRingProtector protector =
                SecretKeyRingProtector.unlockEachKeyWith(Passphrase.fromPassword(originalPassphrase), secretKey);
        Passphrase subkeyPassphrase = Passphrase.fromPassword("subk3yP4ssphr4s3");
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .addSubKey(
                        KeySpec.getBuilder(KeyType.ECDH(EllipticCurve._BRAINPOOLP512R1), KeyFlag.ENCRYPT_COMMS)
                                .build(),
                        subkeyPassphrase,
                        protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        assertEquals(4, info.getSecretKeys().size());
        assertEquals(4, info.getPublicKeys().size());
        List<OpenPGPCertificate.OpenPGPComponentKey> encryptionSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.COMMUNICATIONS);
        assertEquals(2, encryptionSubkeys.size());
        UnlockSecretKey.unlockSecretKey(secretKey.getSecretKey(encryptionSubkeys.get(1).getKeyIdentifier()), subkeyPassphrase);
    }

    /**
     * This example demonstrates how to set a key expiration date.
     * The provided expiration date will be set on each user-id certification signature.
     */
    @Test
    public void setKeyExpirationDate() {
        Date expirationDate = DateUtil.parseUTCDate("2030-06-24 12:44:56 UTC");

        SecretKeyRingProtector protector = SecretKeyRingProtector
                .unlockEachKeyWith(Passphrase.fromPassword(originalPassphrase), secretKey);
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .setExpirationDate(expirationDate, protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        assertEquals(DateUtil.formatUTCDate(expirationDate),
                DateUtil.formatUTCDate(info.getPrimaryKeyExpirationDate()));
        assertEquals(DateUtil.formatUTCDate(expirationDate),
                DateUtil.formatUTCDate(info.getExpirationDateForUse(KeyFlag.ENCRYPT_COMMS)));
        assertEquals(DateUtil.formatUTCDate(expirationDate),
                DateUtil.formatUTCDate(info.getExpirationDateForUse(KeyFlag.SIGN_DATA)));
    }

    /**
     * This example demonstrates how to revoke a user-id on a key.
     */
    @Test
    public void revokeUserId() throws PGPException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockEachKeyWith(
                Passphrase.fromPassword(originalPassphrase), secretKey);
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .addUserId("alcie@pgpainless.org", protector)
                .done();
        // Initially the user-id is valid
        assertTrue(PGPainless.inspectKeyRing(secretKey).isUserIdValid("alcie@pgpainless.org"));

        // Revoke the second user-id
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .revokeUserId("alcie@pgpainless.org", protector)
                .done();
        // Now the user-id is no longer valid
        assertFalse(PGPainless.inspectKeyRing(secretKey).isUserIdValid("alcie@pgpainless.org"));
    }
}
