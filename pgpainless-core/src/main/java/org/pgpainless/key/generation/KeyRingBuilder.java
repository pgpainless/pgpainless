/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.key.generation;


import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh.XDHCurve;
import org.pgpainless.key.util.UserId;
import org.pgpainless.provider.ProviderFactory;
import org.pgpainless.util.Passphrase;
import org.pgpainless.signature.subpackets.SignatureSubpacketGeneratorUtil;

public class KeyRingBuilder implements KeyRingBuilderInterface {

    private static final Logger LOGGER = Logger.getLogger(KeyRingBuilder.class.getName());

    private final Charset UTF8 = Charset.forName("UTF-8");

    private final List<KeySpec> keySpecs = new ArrayList<>();
    private String userId;
    private final Set<String> additionalUserIds = new LinkedHashSet<>();
    private Passphrase passphrase;
    private Date expirationDate = null;

    /**
     * Creates a simple, unencrypted RSA KeyPair of length {@code length} with user-id {@code userId}.
     * The KeyPair consists of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     *
     * @return {@link PGPSecretKeyRing} containing the KeyPair.
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
     */
    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull String userId, @Nonnull RsaLength length, String password)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        WithAdditionalUserIdOrPassphrase builder = this
                .withPrimaryKey(
                        KeySpec.getBuilder(KeyType.RSA(length))
                                .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS)
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId);

        if (password == null) {
            return builder.withoutPassphrase().build();
        } else {
            return builder.withPassphrase(new Passphrase(password.toCharArray())).build();
        }
    }

    /**
     * Creates a key ring consisting of an ed25519 EdDSA primary key and a curve25519 XDH subkey.
     * The EdDSA primary key is used for signing messages and certifying the sub key.
     * The XDH subkey is used for encryption and decryption of messages.
     *
     * @param userId user-id
     *
     * @return {@link PGPSecretKeyRing} containing the key pairs.
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
     */
    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull String userId, String password)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        WithAdditionalUserIdOrPassphrase builder = this
                .withSubKey(
                        KeySpec.getBuilder(KeyType.XDH(XDHCurve._X25519))
                                .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
                                .withDefaultAlgorithms())
                .withPrimaryKey(
                        KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                                .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId);

        if (password == null) {
            return builder.withoutPassphrase().build();
        } else {
            return builder.withPassphrase(new Passphrase(password.toCharArray())).build();
        }
    }

    /**
     * Generate a modern PGP key ring consisting of an ed25519 EdDSA primary key which is used to certify
     * an X25519 XDH encryption subkey and an ed25519 EdDSA signing key.
     *
     * @param userId primary user id
     * @param password passphrase or null if the key should be unprotected.
     * @return key ring
     */
    public PGPSecretKeyRing modernKeyRing(String userId, String password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        WithAdditionalUserIdOrPassphrase builder = this
                .withSubKey(
                        KeySpec.getBuilder(KeyType.XDH(XDHCurve._X25519))
                                .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
                                .withDefaultAlgorithms())
                .withSubKey(
                        KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                                .withKeyFlags(KeyFlag.SIGN_DATA)
                                .withDefaultAlgorithms())
                .withPrimaryKey(
                        KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                                .withKeyFlags(KeyFlag.CERTIFY_OTHER)
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId);

        if (password == null) {
            return builder.withoutPassphrase().build();
        } else {
            return builder.withPassphrase(new Passphrase(password.toCharArray())).build();
        }
    }

    @Override
    public KeyRingBuilderInterface withSubKey(@Nonnull KeySpec type) {
        KeyRingBuilder.this.keySpecs.add(type);
        return this;
    }

    @Override
    public WithPrimaryUserId withPrimaryKey(@Nonnull KeySpec spec) {
        verifyMasterKeyCanCertify(spec);

        KeyRingBuilder.this.keySpecs.add(0, spec);
        return new WithPrimaryUserIdImpl();
    }

    private void verifyMasterKeyCanCertify(KeySpec spec) {
        if (!hasCertifyOthersFlag(spec)) {
            throw new IllegalArgumentException("Certification Key MUST have KeyFlag CERTIFY_OTHER");
        }
        if (!keyIsCertificationCapable(spec)) {
            throw new IllegalArgumentException("Key algorithm " + spec.getKeyType().getName() + " is not capable of creating certifications.");
        }
    }

    private boolean hasCertifyOthersFlag(KeySpec keySpec) {
        return SignatureSubpacketGeneratorUtil.hasKeyFlag(KeyFlag.CERTIFY_OTHER, keySpec.getSubpacketGenerator());
    }

    private boolean keyIsCertificationCapable(KeySpec keySpec) {
        return keySpec.getKeyType().canCertify();
    }

    class WithPrimaryUserIdImpl implements WithPrimaryUserId {

        @Override
        public WithAdditionalUserIdOrPassphrase withPrimaryUserId(@Nonnull String userId) {
            KeyRingBuilder.this.userId = userId.trim();
            return new WithAdditionalUserIdOrPassphraseImpl();
        }

        @Override
        public WithAdditionalUserIdOrPassphrase withPrimaryUserId(@Nonnull byte[] userId) {
            return withPrimaryUserId(new String(userId, UTF8));
        }
    }

    class WithAdditionalUserIdOrPassphraseImpl implements WithAdditionalUserIdOrPassphrase {

        @Override
        public WithAdditionalUserIdOrPassphrase setExpirationDate(@Nonnull Date expirationDate) {
            Date now = new Date();
            if (now.after(expirationDate)) {
                throw new IllegalArgumentException("Expiration date must be in the future.");
            }
            KeyRingBuilder.this.expirationDate = expirationDate;
            return this;
        }

        @Override
        public WithAdditionalUserIdOrPassphrase withAdditionalUserId(@Nonnull String userId) {
            String trimmed = userId.trim();
            if (KeyRingBuilder.this.userId.equals(trimmed)) {
                throw new IllegalArgumentException("Additional user-id MUST NOT be equal to primary user-id.");
            }
            KeyRingBuilder.this.additionalUserIds.add(trimmed);
            return this;
        }

        @Override
        public WithAdditionalUserIdOrPassphrase withAdditionalUserId(@Nonnull byte[] userId) {
            return withAdditionalUserId(new String(userId, UTF8));
        }

        @Override
        public Build withPassphrase(@Nonnull Passphrase passphrase) {
            KeyRingBuilder.this.passphrase = passphrase;
            return new BuildImpl();
        }

        @Override
        public Build withoutPassphrase() {
            KeyRingBuilder.this.passphrase = null;
            return new BuildImpl();
        }

        class BuildImpl implements Build {

            private PGPSignatureGenerator signatureGenerator;
            private PGPDigestCalculator digestCalculator;
            private PBESecretKeyEncryptor secretKeyEncryptor;

            @Override
            public PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException,
                    InvalidAlgorithmParameterException {
                digestCalculator = buildDigestCalculator();
                secretKeyEncryptor = buildSecretKeyEncryptor();
                PBESecretKeyDecryptor secretKeyDecryptor = buildSecretKeyDecryptor();

                if (passphrase != null) {
                    passphrase.clear();
                }

                // First key is the Master Key
                KeySpec certKeySpec = keySpecs.remove(0);

                // Generate Master Key
                PGPKeyPair certKey = generateKeyPair(certKeySpec);
                PGPContentSignerBuilder signer = buildContentSigner(certKey);
                signatureGenerator = new PGPSignatureGenerator(signer);
                PGPSignatureSubpacketGenerator hashedSubPacketGenerator = certKeySpec.getSubpacketGenerator();
                hashedSubPacketGenerator.setPrimaryUserID(false, true);
                if (expirationDate != null) {
                    SignatureSubpacketGeneratorUtil.setExpirationDateInSubpacketGenerator(
                            expirationDate, new Date(), hashedSubPacketGenerator);
                }
                PGPSignatureSubpacketVector hashedSubPackets = hashedSubPacketGenerator.generate();

                // Generator which the user can get the key pair from
                PGPKeyRingGenerator ringGenerator = buildRingGenerator(certKey, signer, hashedSubPackets);

                addSubKeys(certKey, ringGenerator);

                // Generate secret key ring with only primary user id
                PGPSecretKeyRing secretKeyRing = ringGenerator.generateSecretKeyRing();

                Iterator<PGPSecretKey> secretKeys = secretKeyRing.getSecretKeys();

                // Attempt to add additional user-ids to the primary public key
                PGPPublicKey primaryPubKey = secretKeys.next().getPublicKey();
                PGPPrivateKey privateKey = secretKeyRing.getSecretKey().extractPrivateKey(secretKeyDecryptor);
                for (String additionalUserId : additionalUserIds) {
                    signatureGenerator.init(SignatureType.POSITIVE_CERTIFICATION.getCode(), privateKey);
                    PGPSignature additionalUserIdSignature =
                            signatureGenerator.generateCertification(additionalUserId, primaryPubKey);
                    primaryPubKey = PGPPublicKey.addCertification(primaryPubKey,
                            additionalUserId, additionalUserIdSignature);
                }

                // "reassemble" secret key ring with modified primary key
                PGPSecretKey primarySecKey = new PGPSecretKey(
                        privateKey,
                        primaryPubKey, digestCalculator, true, secretKeyEncryptor);
                List<PGPSecretKey> secretKeyList = new ArrayList<>();
                secretKeyList.add(primarySecKey);
                while (secretKeys.hasNext()) {
                    secretKeyList.add(secretKeys.next());
                }
                secretKeyRing = new PGPSecretKeyRing(secretKeyList);

                return secretKeyRing;
            }

            private PGPKeyRingGenerator buildRingGenerator(PGPKeyPair certKey,
                                                           PGPContentSignerBuilder signer,
                                                           PGPSignatureSubpacketVector hashedSubPackets)
                    throws PGPException {
                return new PGPKeyRingGenerator(
                        SignatureType.POSITIVE_CERTIFICATION.getCode(), certKey,
                        userId, digestCalculator,
                        hashedSubPackets, null, signer, secretKeyEncryptor);
            }

            private void addSubKeys(PGPKeyPair primaryKey, PGPKeyRingGenerator ringGenerator)
                    throws NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException {
                for (KeySpec subKeySpec : keySpecs) {
                    PGPKeyPair subKey = generateKeyPair(subKeySpec);
                    if (subKeySpec.isInheritedSubPackets()) {
                        ringGenerator.addSubKey(subKey);
                    } else {
                        PGPSignatureSubpacketVector hashedSubpackets = subKeySpec.getSubpackets();
                        try {
                            hashedSubpackets = addPrimaryKeyBindingSignatureIfNecessary(primaryKey, subKey, hashedSubpackets);
                        } catch (IOException e) {
                            throw new PGPException("Exception while adding primary key binding signature to signing subkey", e);
                        }
                        ringGenerator.addSubKey(subKey, hashedSubpackets, null);
                    }
                }
            }

            private PGPSignatureSubpacketVector addPrimaryKeyBindingSignatureIfNecessary(PGPKeyPair primaryKey, PGPKeyPair subKey, PGPSignatureSubpacketVector hashedSubpackets) throws PGPException, IOException {
                int keyFlagMask = hashedSubpackets.getKeyFlags();
                if (!KeyFlag.hasKeyFlag(keyFlagMask, KeyFlag.SIGN_DATA) && !KeyFlag.hasKeyFlag(keyFlagMask, KeyFlag.CERTIFY_OTHER)) {
                    return hashedSubpackets;
                }

                PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(buildContentSigner(subKey));
                signatureGenerator.init(SignatureType.PRIMARYKEY_BINDING.getCode(), subKey.getPrivateKey());
                PGPSignature primaryKeyBindingSig = signatureGenerator.generateCertification(primaryKey.getPublicKey(), subKey.getPublicKey());
                PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator(hashedSubpackets);
                subpacketGenerator.addEmbeddedSignature(false, primaryKeyBindingSig);
                return subpacketGenerator.generate();
            }

            private PGPContentSignerBuilder buildContentSigner(PGPKeyPair certKey) {
                HashAlgorithm hashAlgorithm = PGPainless.getPolicy().getSignatureHashAlgorithmPolicy().defaultHashAlgorithm();
                return ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        certKey.getPublicKey().getAlgorithm(),
                        hashAlgorithm.getAlgorithmId());
            }

            private PBESecretKeyEncryptor buildSecretKeyEncryptor() {
                SymmetricKeyAlgorithm keyEncryptionAlgorithm = PGPainless.getPolicy().getSymmetricKeyAlgorithmPolicy()
                        .getDefaultSymmetricKeyAlgorithm();
                PBESecretKeyEncryptor encryptor = passphrase == null || passphrase.isEmpty() ?
                        null : // unencrypted key pair, otherwise AES-256 encrypted
                        ImplementationFactory.getInstance().getPBESecretKeyEncryptor(
                                keyEncryptionAlgorithm, digestCalculator, passphrase);
                return encryptor;
            }

            private PBESecretKeyDecryptor buildSecretKeyDecryptor() throws PGPException {
                PBESecretKeyDecryptor decryptor = passphrase == null || passphrase.isEmpty() ?
                        null :
                        ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase);
                return decryptor;
            }

            private PGPDigestCalculator buildDigestCalculator() throws PGPException {
                return ImplementationFactory.getInstance().getPGPDigestCalculator(HashAlgorithm.SHA1);
            }
        }
    }

    public static PGPKeyPair generateKeyPair(KeySpec spec)
            throws NoSuchAlgorithmException, PGPException,
            InvalidAlgorithmParameterException {
        KeyType type = spec.getKeyType();
        KeyPairGenerator certKeyGenerator = KeyPairGenerator.getInstance(type.getName(),
                ProviderFactory.getProvider());
        certKeyGenerator.initialize(type.getAlgorithmSpec());

        // Create raw Key Pair
        KeyPair keyPair = certKeyGenerator.generateKeyPair();

        // Form PGP key pair
        PGPKeyPair pgpKeyPair;
        try {
            pgpKeyPair = ImplementationFactory.getInstance().getPGPKeyPair(type.getAlgorithm(), keyPair, new Date());
        } catch (PGPException e) {
            // When generating EdDSA keys, the private key has an encoding length of 33 instead of 34, which results
            //  in an exception. Therefore we just try again as a workaround.
            LOGGER.log(Level.INFO, "Private key has wrong length. Try again.", e);
            pgpKeyPair = generateKeyPair(spec);
        }
        return pgpKeyPair;
    }
}
