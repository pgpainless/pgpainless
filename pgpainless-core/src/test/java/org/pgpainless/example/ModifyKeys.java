package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
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
import org.pgpainless.util.Passphrase;

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

    @Test
    public void addSubkey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        // Protector for unlocking the existing secret key
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAllKeysWith(Passphrase.fromPassword(originalPassphrase), secretKey);
        Passphrase subkeyPassphrase = Passphrase.fromPassword("subk3yP4ssphr4s3");
        assertEquals(1, new KeyRingInfo(secretKey).getEncryptionSubkeys(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS).size());
        secretKey = PGPainless.modifyKeyRing(secretKey)
                .addSubKey(
                        KeySpec.getBuilder(KeyType.ECDH(EllipticCurve._BRAINPOOLP512R1))
                                .withKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                                .withDefaultAlgorithms(),
                        subkeyPassphrase,
                        protector)
                .done();


        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        assertEquals(4, info.getSecretKeys().size());
        assertEquals(4, info.getPublicKeys().size());
        assertEquals(2, info.getEncryptionSubkeys(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS).size());

    }
}
