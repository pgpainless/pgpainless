// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification.secretkeyring;

import static org.pgpainless.util.CollectionUtils.concat;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.AlgorithmSuite;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.CachingSecretKeyRingProtector;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.protection.fixes.S2KUsageFix;
import org.pgpainless.key.protection.passphrase_provider.SolitaryPassphraseProvider;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.signature.builder.DirectKeySignatureBuilder;
import org.pgpainless.signature.builder.RevocationSignatureBuilder;
import org.pgpainless.signature.builder.SelfSignatureBuilder;
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.BCUtil;
import org.pgpainless.util.CollectionUtils;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.selection.userid.SelectUserId;

public class SecretKeyRingEditor implements SecretKeyRingEditorInterface {

    private PGPSecretKeyRing secretKeyRing;

    public SecretKeyRingEditor(PGPSecretKeyRing secretKeyRing) {
        if (secretKeyRing == null) {
            throw new NullPointerException("SecretKeyRing MUST NOT be null.");
        }
        this.secretKeyRing = secretKeyRing;
    }

    @Override
    public SecretKeyRingEditorInterface addUserId(
            @Nonnull CharSequence userId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {
        return addUserId(userId, null, secretKeyRingProtector);
    }

    @Override
    public SecretKeyRingEditorInterface addUserId(
            @Nonnull CharSequence userId,
            @Nullable SelfSignatureSubpackets.Callback signatureSubpacketCallback,
            @Nonnull SecretKeyRingProtector protector)
            throws PGPException {
        String sanitizeUserId = sanitizeUserId(userId);

        // user-id certifications live on the primary key
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();

        // retain key flags from previous signature
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        if (info.isHardRevoked(userId.toString())) {
            throw new IllegalArgumentException("User-ID " + userId + " is hard revoked and cannot be re-certified.");
        }
        List<KeyFlag> keyFlags = info.getKeyFlagsOf(info.getKeyId());

        Set<HashAlgorithm> hashAlgorithmPreferences;
        Set<SymmetricKeyAlgorithm> symmetricKeyAlgorithmPreferences;
        Set<CompressionAlgorithm> compressionAlgorithmPreferences;
        try {
            hashAlgorithmPreferences = info.getPreferredHashAlgorithms();
            symmetricKeyAlgorithmPreferences = info.getPreferredSymmetricKeyAlgorithms();
            compressionAlgorithmPreferences = info.getPreferredCompressionAlgorithms();
        } catch (IllegalStateException e) {
            // missing user-id sig
            AlgorithmSuite algorithmSuite = AlgorithmSuite.getDefaultAlgorithmSuite();
            hashAlgorithmPreferences = algorithmSuite.getHashAlgorithms();
            symmetricKeyAlgorithmPreferences = algorithmSuite.getSymmetricKeyAlgorithms();
            compressionAlgorithmPreferences = algorithmSuite.getCompressionAlgorithms();
        }

        SelfSignatureBuilder builder = new SelfSignatureBuilder(primaryKey, protector);
        builder.setSignatureType(SignatureType.POSITIVE_CERTIFICATION);

        // Retain signature subpackets of previous signatures
        builder.getHashedSubpackets().setKeyFlags(keyFlags);
        builder.getHashedSubpackets().setPreferredHashAlgorithms(hashAlgorithmPreferences);
        builder.getHashedSubpackets().setPreferredSymmetricKeyAlgorithms(symmetricKeyAlgorithmPreferences);
        builder.getHashedSubpackets().setPreferredCompressionAlgorithms(compressionAlgorithmPreferences);
        builder.getHashedSubpackets().setFeatures(Feature.MODIFICATION_DETECTION);

        builder.applyCallback(signatureSubpacketCallback);

        PGPSignature signature = builder.build(primaryKey.getPublicKey(), sanitizeUserId);
        secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, sanitizeUserId, signature);

        return this;
    }

    @Override
    public SecretKeyRingEditorInterface addPrimaryUserId(
            @Nonnull CharSequence userId, @Nonnull SecretKeyRingProtector protector)
            throws PGPException {

        // Determine previous key expiration date
        PGPPublicKey primaryKey = secretKeyRing.getSecretKey().getPublicKey();
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        String primaryUserId = info.getPrimaryUserId();
        PGPSignature signature = primaryUserId == null ?
                info.getLatestDirectKeySelfSignature() : info.getLatestUserIdCertification(primaryUserId);
        final Date previousKeyExpiration = signature == null ? null :
            SignatureSubpacketsUtil.getKeyExpirationTimeAsDate(signature, primaryKey);

        // Add new primary user-id signature
        addUserId(
                userId,
                new SelfSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                        hashedSubpackets.setPrimaryUserId();
                        if (previousKeyExpiration != null) {
                            hashedSubpackets.setKeyExpirationTime(primaryKey, previousKeyExpiration);
                        } else {
                            hashedSubpackets.setKeyExpirationTime(null);
                        }
                    }
                },
                protector);

        // unmark previous primary user-ids to be non-primary
        info = PGPainless.inspectKeyRing(secretKeyRing);
        for (String otherUserId : info.getBoundButPossiblyExpiredUserIds()) {
            if (userId.toString().equals(otherUserId)) {
                continue;
            }

            // We need to unmark this user-id as primary
            if (info.getLatestUserIdCertification(otherUserId).getHashedSubPackets().isPrimaryUserID()) {
                addUserId(otherUserId, new SelfSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                        hashedSubpackets.setPrimaryUserId(null);
                        hashedSubpackets.setKeyExpirationTime(null); // non-primary
                    }
                }, protector);
            }
        }
        return this;
    }

    // TODO: Move to utility class?
    private String sanitizeUserId(@Nonnull CharSequence userId) {
        // TODO: Further research how to sanitize user IDs.
        //  eg. what about newlines?
        return userId.toString().trim();
    }

    @Override
    public SecretKeyRingEditorInterface addSubKey(
            @Nonnull KeySpec keySpec,
            @Nonnull Passphrase subKeyPassphrase,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPKeyPair keyPair = KeyRingBuilder.generateKeyPair(keySpec);

        SecretKeyRingProtector subKeyProtector = PasswordBasedSecretKeyRingProtector
                .forKeyId(keyPair.getKeyID(), subKeyPassphrase);

        SelfSignatureSubpackets.Callback callback = new SelfSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                SignatureSubpacketsHelper.applyFrom(keySpec.getSubpackets(), (SignatureSubpackets) hashedSubpackets);
            }
        };

        List<KeyFlag> keyFlags = KeyFlag.fromBitmask(keySpec.getSubpackets().getKeyFlags());
        KeyFlag firstFlag = keyFlags.remove(0);
        KeyFlag[] otherFlags = keyFlags.toArray(new KeyFlag[0]);

        return addSubKey(keyPair, callback, subKeyProtector, secretKeyRingProtector, firstFlag, otherFlags);
    }

    @Override
    public SecretKeyRingEditorInterface addSubKey(
            @Nonnull KeySpec keySpec,
            @Nullable Passphrase subkeyPassphrase,
            @Nullable SelfSignatureSubpackets.Callback subpacketsCallback,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPKeyPair keyPair = KeyRingBuilder.generateKeyPair(keySpec);

        SecretKeyRingProtector subKeyProtector = PasswordBasedSecretKeyRingProtector
                .forKeyId(keyPair.getKeyID(), subkeyPassphrase);

        List<KeyFlag> keyFlags = KeyFlag.fromBitmask(keySpec.getSubpackets().getKeyFlags());
        KeyFlag firstFlag = keyFlags.remove(0);
        KeyFlag[] otherFlags = keyFlags.toArray(new KeyFlag[0]);

        return addSubKey(keyPair, subpacketsCallback, subKeyProtector, secretKeyRingProtector, firstFlag, otherFlags);
    }

    @Override
    public SecretKeyRingEditorInterface addSubKey(
            @Nonnull PGPKeyPair subkey,
            @Nullable SelfSignatureSubpackets.Callback bindingSignatureCallback,
            @Nonnull SecretKeyRingProtector subkeyProtector,
            @Nonnull SecretKeyRingProtector primaryKeyProtector,
            @Nonnull KeyFlag keyFlag,
            KeyFlag... additionalKeyFlags)
            throws PGPException, IOException, NoSuchAlgorithmException {
        KeyFlag[] flags = concat(keyFlag, additionalKeyFlags);
        PublicKeyAlgorithm subkeyAlgorithm = PublicKeyAlgorithm.fromId(subkey.getPublicKey().getAlgorithm());
        SignatureSubpacketsUtil.assureKeyCanCarryFlags(subkeyAlgorithm);

        // check key against public key algorithm policy
        PublicKeyAlgorithm publicKeyAlgorithm = PublicKeyAlgorithm.fromId(subkey.getPublicKey().getAlgorithm());
        int bitStrength = BCUtil.getBitStrength(subkey.getPublicKey());
        if (!PGPainless.getPolicy().getPublicKeyAlgorithmPolicy().isAcceptable(publicKeyAlgorithm, bitStrength)) {
            throw new IllegalArgumentException("Public key algorithm policy violation: " +
                    publicKeyAlgorithm + " with bit strength " + bitStrength + " is not acceptable.");
        }

        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        PublicKeyAlgorithm signingKeyAlgorithm = PublicKeyAlgorithm.fromId(primaryKey.getPublicKey().getAlgorithm());
        HashAlgorithm hashAlgorithm = HashAlgorithmNegotiator
                .negotiateSignatureHashAlgorithm(PGPainless.getPolicy())
                .negotiateHashAlgorithm(info.getPreferredHashAlgorithms());

        // While we'd like to rely on our own BindingSignatureBuilder implementation,
        //  unfortunately we have to use BCs PGPKeyRingGenerator class since there is no public constructor
        //  for subkeys. See https://github.com/bcgit/bc-java/pull/1063
        PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(
                secretKeyRing,
                primaryKeyProtector.getDecryptor(primaryKey.getKeyID()),
                ImplementationFactory.getInstance().getV4FingerprintCalculator(),
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        signingKeyAlgorithm, hashAlgorithm),
                subkeyProtector.getEncryptor(subkey.getKeyID()));

        SelfSignatureSubpackets hashedSubpackets = SignatureSubpackets.createHashedSubpackets(primaryKey.getPublicKey());
        SelfSignatureSubpackets unhashedSubpackets = SignatureSubpackets.createEmptySubpackets();
        hashedSubpackets.setKeyFlags(flags);

        if (bindingSignatureCallback != null) {
            bindingSignatureCallback.modifyHashedSubpackets(hashedSubpackets);
            bindingSignatureCallback.modifyUnhashedSubpackets(unhashedSubpackets);
        }

        boolean isSigningKey = CollectionUtils.contains(flags, KeyFlag.SIGN_DATA) ||
                CollectionUtils.contains(flags, KeyFlag.CERTIFY_OTHER);
        PGPContentSignerBuilder primaryKeyBindingSigner = null;
        if (isSigningKey) {
            primaryKeyBindingSigner = ImplementationFactory.getInstance().getPGPContentSignerBuilder(subkeyAlgorithm, hashAlgorithm);
        }

        ringGenerator.addSubKey(subkey,
                SignatureSubpacketsHelper.toVector((SignatureSubpackets) hashedSubpackets),
                SignatureSubpacketsHelper.toVector((SignatureSubpackets) unhashedSubpackets),
                primaryKeyBindingSigner);

        secretKeyRing = ringGenerator.generateSecretKeyRing();

        return this;
    }

    @Override
    public SecretKeyRingEditorInterface revoke(@Nonnull SecretKeyRingProtector secretKeyRingProtector,
                                               @Nullable RevocationAttributes revocationAttributes)
            throws PGPException {
        RevocationSignatureSubpackets.Callback callback = callbackFromRevocationAttributes(revocationAttributes);
        return revoke(secretKeyRingProtector, callback);
    }

    @Override
    public SecretKeyRingEditorInterface revoke(@Nonnull SecretKeyRingProtector secretKeyRingProtector,
                                               @Nullable RevocationSignatureSubpackets.Callback subpacketsCallback)
            throws PGPException {
        return revokeSubKey(secretKeyRing.getSecretKey().getKeyID(), secretKeyRingProtector, subpacketsCallback);
    }

    @Override
    public SecretKeyRingEditorInterface revokeSubKey(long subKeyId,
                                                     SecretKeyRingProtector protector,
                                                     RevocationAttributes revocationAttributes)
            throws PGPException {
        RevocationSignatureSubpackets.Callback callback = callbackFromRevocationAttributes(revocationAttributes);
        return revokeSubKey(subKeyId, protector, callback);
    }

    @Override
    public SecretKeyRingEditorInterface revokeSubKey(long keyID,
                                                     @Nonnull SecretKeyRingProtector secretKeyRingProtector,
                                                     @Nullable RevocationSignatureSubpackets.Callback subpacketsCallback)
            throws PGPException {
        // retrieve subkey to be revoked
        PGPPublicKey revokeeSubKey = KeyRingUtils.requirePublicKeyFrom(secretKeyRing, keyID);
        // create revocation
        PGPSignature subKeyRevocation = generateRevocation(secretKeyRingProtector, revokeeSubKey,
                subpacketsCallback);
        // inject revocation sig into key ring
        secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, revokeeSubKey, subKeyRevocation);
        return this;
    }

    @Override
    public PGPSignature createRevocationCertificate(@Nonnull SecretKeyRingProtector secretKeyRingProtector,
                                                    @Nullable RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey revokeeSubKey = secretKeyRing.getPublicKey();
        PGPSignature revocationCertificate = generateRevocation(
                secretKeyRingProtector, revokeeSubKey, callbackFromRevocationAttributes(revocationAttributes));
        return revocationCertificate;
    }

    @Override
    public PGPSignature createRevocationCertificate(
            long subkeyId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException {
        PGPPublicKey revokeeSubkey = KeyRingUtils.requirePublicKeyFrom(secretKeyRing, subkeyId);
        RevocationSignatureSubpackets.Callback callback = callbackFromRevocationAttributes(revocationAttributes);
        return generateRevocation(secretKeyRingProtector, revokeeSubkey, callback);
    }

    @Override
    public PGPSignature createRevocationCertificate(
            long subkeyId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback certificateSubpacketsCallback)
            throws PGPException {
        PGPPublicKey revokeeSubkey = KeyRingUtils.requirePublicKeyFrom(secretKeyRing, subkeyId);
        return generateRevocation(secretKeyRingProtector, revokeeSubkey, certificateSubpacketsCallback);
    }

    private PGPSignature generateRevocation(@Nonnull SecretKeyRingProtector protector,
                                            @Nonnull PGPPublicKey revokeeSubKey,
                                            @Nullable RevocationSignatureSubpackets.Callback callback)
            throws PGPException {
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        SignatureType signatureType = revokeeSubKey.isMasterKey() ?
                SignatureType.KEY_REVOCATION : SignatureType.SUBKEY_REVOCATION;

        RevocationSignatureBuilder signatureBuilder =
                new RevocationSignatureBuilder(signatureType, primaryKey, protector);
        signatureBuilder.applyCallback(callback);
        PGPSignature revocation = signatureBuilder.build(revokeeSubKey);
        return revocation;
    }

    private static RevocationSignatureSubpackets.Callback callbackFromRevocationAttributes(
            @Nullable RevocationAttributes attributes) {
        return new RevocationSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(RevocationSignatureSubpackets hashedSubpackets) {
                if (attributes != null) {
                    hashedSubpackets.setRevocationReason(attributes);
                }
            }
        };
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserId(
            @Nonnull CharSequence userId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException {
        if (revocationAttributes != null) {
            RevocationAttributes.Reason reason = revocationAttributes.getReason();
            if (reason != RevocationAttributes.Reason.NO_REASON
                    && reason != RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID) {
                throw new IllegalArgumentException("Revocation reason must either be NO_REASON or USER_ID_NO_LONGER_VALID");
            }
        }

        RevocationSignatureSubpackets.Callback callback = new RevocationSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(RevocationSignatureSubpackets hashedSubpackets) {
                if (revocationAttributes != null) {
                    hashedSubpackets.setRevocationReason(false, revocationAttributes);
                }
            }
        };

        return revokeUserId(userId, secretKeyRingProtector, callback);
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserId(
            @Nonnull CharSequence userId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback subpacketCallback)
            throws PGPException {
        String sanitized = sanitizeUserId(userId);
        return revokeUserIds(
                SelectUserId.exactMatch(sanitized),
                secretKeyRingProtector,
                subpacketCallback);
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserIds(
            @Nonnull SelectUserId userIdSelector,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException {

        return revokeUserIds(
                userIdSelector,
                secretKeyRingProtector,
                new RevocationSignatureSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(RevocationSignatureSubpackets hashedSubpackets) {
                        hashedSubpackets.setRevocationReason(revocationAttributes);
                    }
                });
    }

    @Override
    public SecretKeyRingEditorInterface revokeUserIds(
            @Nonnull SelectUserId userIdSelector,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback subpacketsCallback)
            throws PGPException {
        List<String> selected = userIdSelector.selectUserIds(secretKeyRing);
        if (selected.isEmpty()) {
            throw new NoSuchElementException("No matching user-ids found on the key.");
        }

        for (String userId : selected) {
            doRevokeUserId(userId, secretKeyRingProtector, subpacketsCallback);
        }

        return this;
    }

    private SecretKeyRingEditorInterface doRevokeUserId(
            @Nonnull String userId,
            @Nonnull SecretKeyRingProtector protector,
            @Nullable RevocationSignatureSubpackets.Callback callback)
            throws PGPException {
        PGPSecretKey primarySecretKey = secretKeyRing.getSecretKey();
        RevocationSignatureBuilder signatureBuilder = new RevocationSignatureBuilder(
                SignatureType.CERTIFICATION_REVOCATION,
                primarySecretKey,
                protector);

        signatureBuilder.applyCallback(callback);

        PGPSignature revocationSignature = signatureBuilder.build(userId);
        secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, userId, revocationSignature);
        return this;
    }

    @Override
    public SecretKeyRingEditorInterface setExpirationDate(
            @Nullable Date expiration,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {

        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        if (!primaryKey.isMasterKey()) {
            throw new IllegalArgumentException("Key Ring does not appear to contain a primary secret key.");
        }

        // reissue direct key sig
        PGPSignature prevDirectKeySig = getPreviousDirectKeySignature();
        if (prevDirectKeySig != null) {
            PGPSignature directKeySig = reissueDirectKeySignature(expiration, secretKeyRingProtector, prevDirectKeySig);
            secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, primaryKey.getPublicKey(), directKeySig);
        }

        // reissue primary user-id sig
        String primaryUserId = PGPainless.inspectKeyRing(secretKeyRing).getPossiblyExpiredUserId();
        if (primaryUserId != null) {
            PGPSignature prevUserIdSig = getPreviousUserIdSignatures(primaryUserId);
            PGPSignature userIdSig = reissuePrimaryUserIdSig(expiration, secretKeyRingProtector, primaryUserId, prevUserIdSig);
            secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, primaryUserId, userIdSig);
        }

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        for (String userId : info.getValidUserIds()) {
            if (userId.equals(primaryUserId)) {
                continue;
            }

            PGPSignature prevUserIdSig = info.getLatestUserIdCertification(userId);
            if (prevUserIdSig == null) {
                throw new AssertionError("A valid user-id shall never have no user-id signature.");
            }

            if (prevUserIdSig.getHashedSubPackets().isPrimaryUserID()) {
                PGPSignature userIdSig = reissueNonPrimaryUserId(secretKeyRingProtector, userId, prevUserIdSig);
                secretKeyRing = KeyRingUtils.injectCertification(secretKeyRing, primaryUserId, userIdSig);
            }
        }

        return this;
    }

    private PGPSignature reissueNonPrimaryUserId(
            SecretKeyRingProtector secretKeyRingProtector,
            String userId,
            PGPSignature prevUserIdSig)
            throws PGPException {
        SelfSignatureBuilder builder = new SelfSignatureBuilder(secretKeyRing.getSecretKey(), secretKeyRingProtector, prevUserIdSig);
        builder.applyCallback(new SelfSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                // unmark as primary
                hashedSubpackets.setPrimaryUserId(null);
            }
        });
        return builder.build(secretKeyRing.getPublicKey(), userId);
    }

    private PGPSignature reissuePrimaryUserIdSig(
            @Nullable Date expiration,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nonnull String primaryUserId,
            @Nonnull PGPSignature prevUserIdSig)
            throws PGPException {
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        PGPPublicKey publicKey = primaryKey.getPublicKey();

        SelfSignatureBuilder builder = new SelfSignatureBuilder(primaryKey, secretKeyRingProtector, prevUserIdSig);
        builder.applyCallback(new SelfSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                if (expiration != null) {
                    hashedSubpackets.setKeyExpirationTime(true, publicKey.getCreationTime(), expiration);
                } else {
                    hashedSubpackets.setKeyExpirationTime(new KeyExpirationTime(true, 0));
                }
                hashedSubpackets.setPrimaryUserId();
            }
        });
        return builder.build(publicKey, primaryUserId);
    }

    private PGPSignature reissueDirectKeySignature(
            Date expiration,
            SecretKeyRingProtector secretKeyRingProtector,
            PGPSignature prevDirectKeySig)
            throws PGPException {
        PGPSecretKey primaryKey = secretKeyRing.getSecretKey();
        PGPPublicKey publicKey = primaryKey.getPublicKey();
        final Date keyCreationTime = publicKey.getCreationTime();

        DirectKeySignatureBuilder builder = new DirectKeySignatureBuilder(primaryKey, secretKeyRingProtector, prevDirectKeySig);
        builder.applyCallback(new SelfSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                if (expiration != null) {
                    hashedSubpackets.setKeyExpirationTime(keyCreationTime, expiration);
                } else {
                    hashedSubpackets.setKeyExpirationTime(null);
                }
            }
        });

        return builder.build(publicKey);
    }

    private PGPSignature getPreviousDirectKeySignature() {
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        return info.getLatestDirectKeySelfSignature();
    }

    private PGPSignature getPreviousUserIdSignatures(String userId) {
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing);
        return info.getLatestUserIdCertification(userId);
    }

    @Override
    public WithKeyRingEncryptionSettings changePassphraseFromOldPassphrase(
            @Nullable Passphrase oldPassphrase,
            @Nonnull KeyRingProtectionSettings oldProtectionSettings) {
        SecretKeyRingProtector protector = new PasswordBasedSecretKeyRingProtector(
                oldProtectionSettings,
                new SolitaryPassphraseProvider(oldPassphrase));

        return new WithKeyRingEncryptionSettingsImpl(null, protector);
    }

    @Override
    public WithKeyRingEncryptionSettings changeSubKeyPassphraseFromOldPassphrase(
            @Nonnull Long keyId,
            @Nullable Passphrase oldPassphrase,
            @Nonnull KeyRingProtectionSettings oldProtectionSettings) {
        Map<Long, Passphrase> passphraseMap = Collections.singletonMap(keyId, oldPassphrase);
        SecretKeyRingProtector protector = new CachingSecretKeyRingProtector(
                passphraseMap, oldProtectionSettings, null);

        return new WithKeyRingEncryptionSettingsImpl(keyId, protector);
    }

    @Override
    public PGPSecretKeyRing done() {
        return secretKeyRing;
    }

    private final class WithKeyRingEncryptionSettingsImpl implements WithKeyRingEncryptionSettings {

        private final Long keyId;
        // Protector to unlock the key with the old passphrase
        private final SecretKeyRingProtector oldProtector;

        /**
         * Builder for selecting protection settings.
         *
         * If the keyId is null, the whole keyRing will get the same new passphrase.
         *
         * @param keyId id of the subkey whose passphrase will be changed, or null.
         * @param oldProtector protector do unlock the key/ring.
         */
        private WithKeyRingEncryptionSettingsImpl(Long keyId, SecretKeyRingProtector oldProtector) {
            this.keyId = keyId;
            this.oldProtector = oldProtector;
        }

        @Override
        public WithPassphrase withSecureDefaultSettings() {
            return withCustomSettings(KeyRingProtectionSettings.secureDefaultSettings());
        }

        @Override
        public WithPassphrase withCustomSettings(KeyRingProtectionSettings settings) {
            return new WithPassphraseImpl(keyId, oldProtector, settings);
        }
    }

    private final class WithPassphraseImpl implements WithPassphrase {

        private final SecretKeyRingProtector oldProtector;
        private final KeyRingProtectionSettings newProtectionSettings;
        private final Long keyId;

        private WithPassphraseImpl(
                Long keyId,
                SecretKeyRingProtector oldProtector,
                KeyRingProtectionSettings newProtectionSettings) {
            this.keyId = keyId;
            this.oldProtector = oldProtector;
            this.newProtectionSettings = newProtectionSettings;
        }

        @Override
        public SecretKeyRingEditorInterface toNewPassphrase(Passphrase passphrase)
                throws PGPException {
            SecretKeyRingProtector newProtector = new PasswordBasedSecretKeyRingProtector(
                    newProtectionSettings, new SolitaryPassphraseProvider(passphrase));

            PGPSecretKeyRing secretKeys = changePassphrase(
                    keyId, SecretKeyRingEditor.this.secretKeyRing, oldProtector, newProtector);
            SecretKeyRingEditor.this.secretKeyRing = secretKeys;

            return SecretKeyRingEditor.this;
        }

        @Override
        public SecretKeyRingEditorInterface toNoPassphrase()
                throws PGPException {
            SecretKeyRingProtector newProtector = new UnprotectedKeysProtector();

            PGPSecretKeyRing secretKeys = changePassphrase(
                    keyId, SecretKeyRingEditor.this.secretKeyRing, oldProtector, newProtector);
            SecretKeyRingEditor.this.secretKeyRing = secretKeys;

            return SecretKeyRingEditor.this;
        }
    }

    private PGPSecretKeyRing changePassphrase(Long keyId,
                                              PGPSecretKeyRing secretKeys,
                                              SecretKeyRingProtector oldProtector,
                                              SecretKeyRingProtector newProtector)
            throws PGPException {
        List<PGPSecretKey> secretKeyList = new ArrayList<>();
        if (keyId == null) {
            // change passphrase of whole key ring
            Iterator<PGPSecretKey> secretKeyIterator = secretKeys.getSecretKeys();
            while (secretKeyIterator.hasNext()) {
                PGPSecretKey secretKey = secretKeyIterator.next();
                secretKey = reencryptPrivateKey(secretKey, oldProtector, newProtector);
                secretKeyList.add(secretKey);
            }
        } else {
            // change passphrase of selected subkey only
            Iterator<PGPSecretKey> secretKeyIterator = secretKeys.getSecretKeys();
            while (secretKeyIterator.hasNext()) {
                PGPSecretKey secretKey = secretKeyIterator.next();
                if (secretKey.getPublicKey().getKeyID() == keyId) {
                    // Re-encrypt only the selected subkey
                    secretKey = reencryptPrivateKey(secretKey, oldProtector, newProtector);
                }
                secretKeyList.add(secretKey);
            }
        }

        PGPSecretKeyRing newRing = new PGPSecretKeyRing(secretKeyList);
        newRing = s2kUsageFixIfNecessary(newRing, newProtector);
        return newRing;
    }

    private PGPSecretKeyRing s2kUsageFixIfNecessary(PGPSecretKeyRing secretKeys, SecretKeyRingProtector protector)
            throws PGPException {
        boolean hasS2KUsageChecksum = false;
        for (PGPSecretKey secKey : secretKeys) {
            if (secKey.getS2KUsage() == SecretKeyPacket.USAGE_CHECKSUM) {
                hasS2KUsageChecksum = true;
                break;
            }
        }
        if (hasS2KUsageChecksum) {
            secretKeys = S2KUsageFix.replaceUsageChecksumWithUsageSha1(
                    secretKeys, protector, true);
        }
        return secretKeys;
    }

    private static PGPSecretKey reencryptPrivateKey(
            PGPSecretKey secretKey,
            SecretKeyRingProtector oldProtector,
            SecretKeyRingProtector newProtector)
            throws PGPException {
        S2K s2k = secretKey.getS2K();
        // If the key uses GNU_DUMMY_S2K, we leave it as is and skip this block
        if (s2k == null || s2k.getType() != S2K.GNU_DUMMY_S2K) {
            long secretKeyId = secretKey.getKeyID();
            PBESecretKeyDecryptor decryptor = oldProtector.getDecryptor(secretKeyId);
            PBESecretKeyEncryptor encryptor = newProtector.getEncryptor(secretKeyId);
            secretKey = PGPSecretKey.copyWithNewPassword(secretKey, decryptor, encryptor);
        }
        return secretKey;
    }
}
