// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.KeyFlags;
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
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.policy.Policy;
import org.pgpainless.provider.ProviderFactory;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper;
import org.pgpainless.s2k.Passphrase;

public class KeyRingBuilder implements KeyRingBuilderInterface<KeyRingBuilder> {

    @SuppressWarnings("CharsetObjectCanBeUsed")
    private final Charset UTF8 = Charset.forName("UTF-8");

    private KeySpec primaryKeySpec;
    private final List<KeySpec> subkeySpecs = new ArrayList<>();
    private final Map<String, SelfSignatureSubpackets.Callback> userIds = new LinkedHashMap<>();
    private Passphrase passphrase = Passphrase.emptyPassphrase();
    private Date expirationDate = null;

    @Override
    public KeyRingBuilder setPrimaryKey(@Nonnull KeySpec keySpec) {
        verifyKeySpecCompliesToPolicy(keySpec, PGPainless.getPolicy());
        verifyMasterKeyCanCertify(keySpec);
        this.primaryKeySpec = keySpec;
        return this;
    }

    @Override
    public KeyRingBuilder addSubkey(@Nonnull KeySpec keySpec) {
        verifyKeySpecCompliesToPolicy(keySpec, PGPainless.getPolicy());
        this.subkeySpecs.add(keySpec);
        return this;
    }

    @Override
    public KeyRingBuilder addUserId(@Nonnull String userId) {
        this.userIds.put(userId.trim(), null);
        return this;
    }

    public KeyRingBuilder addUserId(
            @Nonnull String userId,
            @Nullable SelfSignatureSubpackets.Callback subpacketsCallback) {
        this.userIds.put(userId.trim(), subpacketsCallback);
        return this;
    }

    @Override
    public KeyRingBuilder addUserId(@Nonnull byte[] userId) {
        return addUserId(new String(userId, UTF8));
    }

    @Override
    public KeyRingBuilder setExpirationDate(@Nonnull Date expirationDate) {
        Date now = new Date();
        if (now.after(expirationDate)) {
            throw new IllegalArgumentException("Expiration date must be in the future.");
        }
        this.expirationDate = expirationDate;
        return this;
    }

    @Override
    public KeyRingBuilder setPassphrase(@Nonnull Passphrase passphrase) {
        this.passphrase = passphrase;
        return this;
    }

    private void verifyKeySpecCompliesToPolicy(KeySpec keySpec, Policy policy) {
        PublicKeyAlgorithm publicKeyAlgorithm = keySpec.getKeyType().getAlgorithm();
        int bitStrength = keySpec.getKeyType().getBitStrength();

        if (!policy.getPublicKeyAlgorithmPolicy().isAcceptable(publicKeyAlgorithm, bitStrength)) {
            throw new IllegalArgumentException("Public key algorithm policy violation: " +
                    publicKeyAlgorithm + " with bit strength " + bitStrength + " is not acceptable.");
        }
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
        KeyFlags keyFlags = keySpec.getSubpacketGenerator().getKeyFlagsSubpacket();
        return keyFlags != null && KeyFlag.hasKeyFlag(keyFlags.getFlags(), KeyFlag.CERTIFY_OTHER);
    }

    private boolean keyIsCertificationCapable(KeySpec keySpec) {
        return keySpec.getKeyType().canCertify();
    }

    @Override
    public PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException,
            InvalidAlgorithmParameterException {
        PGPDigestCalculator keyFingerprintCalculator = ImplementationFactory.getInstance().getV4FingerprintCalculator();
        PBESecretKeyEncryptor secretKeyEncryptor = buildSecretKeyEncryptor(keyFingerprintCalculator);
        PBESecretKeyDecryptor secretKeyDecryptor = buildSecretKeyDecryptor();

        passphrase.clear();

        // Generate Primary Key
        PGPKeyPair certKey = generateKeyPair(primaryKeySpec);
        PGPContentSignerBuilder signer = buildContentSigner(certKey);
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signer);

        SignatureSubpackets hashedSubPacketGenerator = primaryKeySpec.getSubpacketGenerator();
        hashedSubPacketGenerator.setIssuerFingerprintAndKeyId(certKey.getPublicKey());
        if (expirationDate != null) {
            hashedSubPacketGenerator.setKeyExpirationTime(certKey.getPublicKey(), expirationDate);
        }
        if (!userIds.isEmpty()) {
            hashedSubPacketGenerator.setPrimaryUserId();
        }

        PGPSignatureSubpacketGenerator generator = new PGPSignatureSubpacketGenerator();
        SignatureSubpacketsHelper.applyTo(hashedSubPacketGenerator, generator);
        PGPSignatureSubpacketVector hashedSubPackets = generator.generate();
        PGPKeyRingGenerator ringGenerator;
        if (userIds.isEmpty()) {
            ringGenerator = new PGPKeyRingGenerator(
                    certKey,
                    keyFingerprintCalculator,
                    hashedSubPackets,
                    null,
                    signer,
                    secretKeyEncryptor);
        } else {
            String primaryUserId = userIds.entrySet().iterator().next().getKey();
            ringGenerator = new PGPKeyRingGenerator(
                    SignatureType.POSITIVE_CERTIFICATION.getCode(), certKey,
                    primaryUserId, keyFingerprintCalculator,
                    hashedSubPackets, null, signer, secretKeyEncryptor);
        }

        addSubKeys(certKey, ringGenerator);

        // Generate secret key ring with only primary user id
        PGPSecretKeyRing secretKeyRing = ringGenerator.generateSecretKeyRing();

        Iterator<PGPSecretKey> secretKeys = secretKeyRing.getSecretKeys();

        // Attempt to add additional user-ids to the primary public key
        PGPPublicKey primaryPubKey = secretKeys.next().getPublicKey();
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKeyRing.getSecretKey(), secretKeyDecryptor);
        Iterator<Map.Entry<String, SelfSignatureSubpackets.Callback>> userIdIterator =
                this.userIds.entrySet().iterator();
        if (userIdIterator.hasNext()) {
            userIdIterator.next(); // Skip primary user id
        }
        while (userIdIterator.hasNext()) {
            Map.Entry<String, SelfSignatureSubpackets.Callback> additionalUserId = userIdIterator.next();
            String userIdString = additionalUserId.getKey();
            SelfSignatureSubpackets.Callback callback = additionalUserId.getValue();
            SelfSignatureSubpackets subpackets = null;
            if (callback == null) {
                subpackets = hashedSubPacketGenerator;
                subpackets.setPrimaryUserId(null);
                // additional user-ids are not primary
            } else {
                subpackets = SignatureSubpackets.createHashedSubpackets(primaryPubKey);
                callback.modifyHashedSubpackets(subpackets);
            }
            signatureGenerator.init(SignatureType.POSITIVE_CERTIFICATION.getCode(), privateKey);
            signatureGenerator.setHashedSubpackets(
                    SignatureSubpacketsHelper.toVector((SignatureSubpackets) subpackets));
            PGPSignature additionalUserIdSignature =
                    signatureGenerator.generateCertification(userIdString, primaryPubKey);
            primaryPubKey = PGPPublicKey.addCertification(primaryPubKey,
                    userIdString, additionalUserIdSignature);
        }

        // "reassemble" secret key ring with modified primary key
        PGPSecretKey primarySecKey = new PGPSecretKey(
                privateKey, primaryPubKey, keyFingerprintCalculator, true, secretKeyEncryptor);
        List<PGPSecretKey> secretKeyList = new ArrayList<>();
        secretKeyList.add(primarySecKey);
        while (secretKeys.hasNext()) {
            secretKeyList.add(secretKeys.next());
        }
        secretKeyRing = new PGPSecretKeyRing(secretKeyList);
        return secretKeyRing;
    }

    private void addSubKeys(PGPKeyPair primaryKey, PGPKeyRingGenerator ringGenerator)
            throws NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException {
        for (KeySpec subKeySpec : subkeySpecs) {
            PGPKeyPair subKey = generateKeyPair(subKeySpec);
            if (subKeySpec.isInheritedSubPackets()) {
                ringGenerator.addSubKey(subKey);
            } else {
                PGPSignatureSubpacketVector hashedSubpackets = subKeySpec.getSubpackets();
                try {
                    hashedSubpackets = addPrimaryKeyBindingSignatureIfNecessary(
                            primaryKey, subKey, hashedSubpackets);
                } catch (IOException e) {
                    throw new PGPException("Exception while adding primary key binding signature to signing subkey", e);
                }
                ringGenerator.addSubKey(subKey, hashedSubpackets, null);
            }
        }
    }

    private PGPSignatureSubpacketVector addPrimaryKeyBindingSignatureIfNecessary(
            PGPKeyPair primaryKey, PGPKeyPair subKey, PGPSignatureSubpacketVector hashedSubpackets)
            throws PGPException, IOException {
        int keyFlagMask = hashedSubpackets.getKeyFlags();
        if (!KeyFlag.hasKeyFlag(keyFlagMask, KeyFlag.SIGN_DATA) &&
                !KeyFlag.hasKeyFlag(keyFlagMask, KeyFlag.CERTIFY_OTHER)) {
            return hashedSubpackets;
        }

        PGPSignatureGenerator bindingSignatureGenerator = new PGPSignatureGenerator(buildContentSigner(subKey));
        bindingSignatureGenerator.init(SignatureType.PRIMARYKEY_BINDING.getCode(), subKey.getPrivateKey());
        PGPSignature primaryKeyBindingSig = bindingSignatureGenerator.generateCertification(primaryKey.getPublicKey(), subKey.getPublicKey());
        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator(hashedSubpackets);
        subpacketGenerator.addEmbeddedSignature(false, primaryKeyBindingSig);
        return subpacketGenerator.generate();
    }

    private PGPContentSignerBuilder buildContentSigner(PGPKeyPair certKey) {
        HashAlgorithm hashAlgorithm = PGPainless.getPolicy()
                .getSignatureHashAlgorithmPolicy().defaultHashAlgorithm();
        return ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                certKey.getPublicKey().getAlgorithm(),
                hashAlgorithm.getAlgorithmId());
    }

    private PBESecretKeyEncryptor buildSecretKeyEncryptor(PGPDigestCalculator keyFingerprintCalculator) {
        SymmetricKeyAlgorithm keyEncryptionAlgorithm = PGPainless.getPolicy()
                .getSymmetricKeyEncryptionAlgorithmPolicy()
                .getDefaultSymmetricKeyAlgorithm();
        if (!passphrase.isValid()) {
            throw new IllegalStateException("Passphrase was cleared.");
        }
        return passphrase.isEmpty() ? null : // unencrypted key pair, otherwise AES-256 encrypted
                ImplementationFactory.getInstance().getPBESecretKeyEncryptor(
                        keyEncryptionAlgorithm, keyFingerprintCalculator, passphrase);
    }

    private PBESecretKeyDecryptor buildSecretKeyDecryptor() throws PGPException {
        if (!passphrase.isValid()) {
            throw new IllegalStateException("Passphrase was cleared.");
        }
        return passphrase.isEmpty() ? null :
                ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase);
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

        Date keyCreationDate = spec.getKeyCreationDate() != null ? spec.getKeyCreationDate() : new Date();

        // Form PGP key pair
        PGPKeyPair pgpKeyPair = ImplementationFactory.getInstance()
                .getPGPKeyPair(type.getAlgorithm(), keyPair, keyCreationDate);
        return pgpKeyPair;
    }
}
