// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.Passphrase;

public final class KeyRingTemplates {

    public KeyRingTemplates() {

    }

    /**
     * Creates a simple, unencrypted RSA KeyPair of length {@code length} with user-id {@code userId}.
     * The KeyPair consists of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     *
     * @return {@link PGPSecretKeyRing} containing the KeyPair.
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull UserId userId, @Nonnull RsaLength length)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleRsaKeyRing(userId.toString(), length);
    }

    /**
     * Creates a simple, unencrypted RSA KeyPair of length {@code length} with user-id {@code userId}.
     * The KeyPair consists of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     *
     * @return {@link PGPSecretKeyRing} containing the KeyPair.
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull String userId, @Nonnull RsaLength length)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleRsaKeyRing(userId, length, null);
    }

    /**
     * Creates a simple RSA KeyPair of length {@code length} with user-id {@code userId}.
     * The KeyPair consists of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     * @param password Password of the key. Can be null for unencrypted keys.
     *
     * @return {@link PGPSecretKeyRing} containing the KeyPair.
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull UserId userId, @Nonnull RsaLength length, String password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleRsaKeyRing(userId.toString(), length, password);
    }

    /**
     * Creates a simple RSA KeyPair of length {@code length} with user-id {@code userId}.
     * The KeyPair consists of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     * @param password Password of the key. Can be null for unencrypted keys.
     *
     * @return {@link PGPSecretKeyRing} containing the KeyPair.
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull String userId, @Nonnull RsaLength length, String password)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyRingBuilder builder = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.RSA(length), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS))
                .addUserId(userId);

        if (!isNullOrEmpty(password)) {
            builder.setPassphrase(Passphrase.fromPassword(password));
        }
        return builder.build();
    }

    /**
     * Creates a key ring consisting of an ed25519 EdDSA primary key and a curve25519 XDH subkey.
     * The EdDSA primary key is used for signing messages and certifying the sub key.
     * The XDH subkey is used for encryption and decryption of messages.
     *
     * @param userId user-id
     *
     * @return {@link PGPSecretKeyRing} containing the key pairs.
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull UserId userId)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleEcKeyRing(userId.toString());
    }

    /**
     * Creates a key ring consisting of an ed25519 EdDSA primary key and a curve25519 XDH subkey.
     * The EdDSA primary key is used for signing messages and certifying the sub key.
     * The XDH subkey is used for encryption and decryption of messages.
     *
     * @param userId user-id
     *
     * @return {@link PGPSecretKeyRing} containing the key pairs.
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull String userId)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleEcKeyRing(userId, null);
    }

    /**
     * Creates a key ring consisting of an ed25519 EdDSA primary key and a curve25519 XDH subkey.
     * The EdDSA primary key is used for signing messages and certifying the sub key.
     * The XDH subkey is used for encryption and decryption of messages.
     *
     * @param userId user-id
     * @param password Password of the private key. Can be null for an unencrypted key.
     *
     * @return {@link PGPSecretKeyRing} containing the key pairs.
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull UserId userId, String password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleEcKeyRing(userId.toString(), password);
    }

    /**
     * Creates a key ring consisting of an ed25519 EdDSA primary key and a X25519 XDH subkey.
     * The EdDSA primary key is used for signing messages and certifying the sub key.
     * The XDH subkey is used for encryption and decryption of messages.
     *
     * @param userId user-id
     * @param password Password of the private key. Can be null for an unencrypted key.
     *
     * @return {@link PGPSecretKeyRing} containing the key pairs.
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull String userId, String password)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyRingBuilder builder = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS))
                .addUserId(userId);

        if (!isNullOrEmpty(password)) {
            builder.setPassphrase(Passphrase.fromPassword(password));
        }
        return builder.build();
    }

    /**
     * Generate a modern PGP key ring consisting of an ed25519 EdDSA primary key which is used to certify
     * an X25519 XDH encryption subkey and an ed25519 EdDSA signing key.
     *
     * @param userId primary user id
     * @param password passphrase or null if the key should be unprotected.
     * @return key ring
     *
     * @throws InvalidAlgorithmParameterException in case of invalid key generation parameters
     * @throws NoSuchAlgorithmException in case of missing algorithm implementation in the crypto provider
     * @throws PGPException in case of an OpenPGP related error
     */
    public PGPSecretKeyRing modernKeyRing(String userId, String password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        KeyRingBuilder builder = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA))
                .addUserId(userId);
        if (!isNullOrEmpty(password)) {
            builder.setPassphrase(Passphrase.fromPassword(password));
        }
        return builder.build();
    }

    private static boolean isNullOrEmpty(String password) {
        return password == null || password.trim().isEmpty();
    }

}
