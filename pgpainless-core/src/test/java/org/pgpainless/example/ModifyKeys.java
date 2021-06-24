/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestUtils;

public class ModifyKeys {

    private final String userId = "alice@pgpainless.org";
    private final String originalPassphrase = "p4ssw0rd";
    private PGPSecretKeyRing secretKey;
    private long primaryKeyId;
    private long encryptionSubkeyId;
    private long signingSubkeyId;

    @BeforeEach
    public void generateKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        secretKey = PGPainless.generateKeyRing()
                .modernKeyRing(userId, originalPassphrase);

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        primaryKeyId = info.getKeyId();
        encryptionSubkeyId = info.getEncryptionSubkeys(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS).get(0).getKeyID();
        signingSubkeyId = info.getSigningSubkeys().get(0).getKeyID();
    }

    /**
     * This example demonstrates how to change the passphrase of a secret key and all its subkeys.
     *
     * @throws PGPException
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
     *
     * @throws PGPException
     */
    @Test
    public void changeSingleSubkeyPassphrase() throws PGPException {
        secretKey = PGPainless.modifyKeyRing(secretKey)
                // Here we change the passphrase of the encryption subkey
                .changeSubKeyPassphraseFromOldPassphrase(encryptionSubkeyId, Passphrase.fromPassword(originalPassphrase))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("cryptP4ssphr4s3"))
                .done();


        // encryption key can now only be unlocked using the new passphrase
        assertThrows(WrongPassphraseException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKey.getSecretKey(encryptionSubkeyId), Passphrase.fromPassword(originalPassphrase)));
        UnlockSecretKey.unlockSecretKey(secretKey.getSecretKey(encryptionSubkeyId), Passphrase.fromPassword("cryptP4ssphr4s3"));
        // primary key remains unchanged
        UnlockSecretKey.unlockSecretKey(secretKey.getSecretKey(primaryKeyId), Passphrase.fromPassword(originalPassphrase));
    }

    /**
     * This example demonstrates how to add an additional user-id to a key.
     *
     * @throws PGPException
     */
    @Test
    public void addUserId() throws PGPException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword(originalPassphrase), secretKey);
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
     *
     * There are two way to add a subkey into an existing key;
     * Either the subkey gets generated on the fly (see below),
     * or the subkey already exists. In the latter case, the user has to provide
     * {@link org.bouncycastle.openpgp.PGPSignatureSubpacketVector PGPSignatureSubpacketVectors} for the binding signature
     * manually.
     *
     * Once the subkey is added, it can be decrypted using the provided subkey passphrase.
     *
     * @throws PGPException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void addSubkey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        // Protector for unlocking the existing secret key
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword(originalPassphrase), secretKey);
        Passphrase subkeyPassphrase = Passphrase.fromPassword("subk3yP4ssphr4s3");
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .addSubKey(
                        KeySpec.getBuilder(KeyType.ECDH(EllipticCurve._BRAINPOOLP512R1))
                                .withKeyFlags(KeyFlag.ENCRYPT_COMMS)
                                .withDefaultAlgorithms(),
                        subkeyPassphrase,
                        protector)
                .done();


        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        assertEquals(4, info.getSecretKeys().size());
        assertEquals(4, info.getPublicKeys().size());
        List<PGPPublicKey> encryptionSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.COMMUNICATIONS);
        assertEquals(2, encryptionSubkeys.size());
        UnlockSecretKey.unlockSecretKey(secretKey.getSecretKey(encryptionSubkeys.get(1).getKeyID()), subkeyPassphrase);
    }

    /**
     * This example demonstrates how to set a key expiration date.
     * The provided expiration date will be set on each user-id certification signature.
     *
     * @throws PGPException
     */
    @Test
    public void setKeyExpirationDate() throws PGPException {
        Date expirationDate = TestUtils.getUTCDate("2030-06-24 12:44:56 UTC");

        SecretKeyRingProtector protector = SecretKeyRingProtector
                .unlockAllKeysWith(Passphrase.fromPassword(originalPassphrase), secretKey);
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .setExpirationDate(expirationDate, protector)
                .done();


        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        assertEquals(TestUtils.formatUTCDate(expirationDate), TestUtils.formatUTCDate(info.getPrimaryKeyExpirationDate()));
        assertEquals(TestUtils.formatUTCDate(expirationDate), TestUtils.formatUTCDate(info.getExpirationDateForUse(KeyFlag.ENCRYPT_COMMS)));
        assertEquals(TestUtils.formatUTCDate(expirationDate), TestUtils.formatUTCDate(info.getExpirationDateForUse(KeyFlag.SIGN_DATA)));
    }

    @Test
    public void setSubkeyExpirationDate() throws PGPException {
        Date expirationDate = TestUtils.getUTCDate("2032-01-13 22:30:01 UTC");

        SecretKeyRingProtector protector = SecretKeyRingProtector
                .unlockAllKeysWith(Passphrase.fromPassword(originalPassphrase), secretKey);
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .setExpirationDate(
                        new OpenPgpV4Fingerprint(secretKey.getPublicKey(encryptionSubkeyId)),
                        expirationDate,
                        protector
                )
                .done();


        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        assertNull(info.getPrimaryKeyExpirationDate());
        assertNull(info.getExpirationDateForUse(KeyFlag.SIGN_DATA));
        assertEquals(TestUtils.formatUTCDate(expirationDate), TestUtils.formatUTCDate(info.getExpirationDateForUse(KeyFlag.ENCRYPT_COMMS)));
    }
}
