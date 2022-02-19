// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.EmbeddedSignature;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.util.RevocationAttributes;

public class SignatureSubpackets
        implements BaseSignatureSubpackets, SelfSignatureSubpackets, CertificationSubpackets, RevocationSignatureSubpackets {

    private SignatureCreationTime signatureCreationTime;
    private SignatureExpirationTime signatureExpirationTime;
    private IssuerKeyID issuerKeyID;
    private IssuerFingerprint issuerFingerprint;
    private final List<NotationData> notationDataList = new ArrayList<>();
    private final List<IntendedRecipientFingerprint> intendedRecipientFingerprintList = new ArrayList<>();
    private final List<RevocationKey> revocationKeyList = new ArrayList<>();
    private Exportable exportable;
    private SignatureTarget signatureTarget;
    private Features features;
    private KeyFlags keyFlags;
    private TrustSignature trust;
    private PreferredAlgorithms preferredCompressionAlgorithms;
    private PreferredAlgorithms preferredSymmetricKeyAlgorithms;
    private PreferredAlgorithms preferredHashAlgorithms;
    private final List<EmbeddedSignature> embeddedSignatureList = new ArrayList<>();
    private SignerUserID signerUserId;
    private KeyExpirationTime keyExpirationTime;
    private PrimaryUserID primaryUserId;
    private Revocable revocable;
    private RevocationReason revocationReason;
    private final List<SignatureSubpacket> residualSubpackets = new ArrayList<>();

    public SignatureSubpackets() {

    }

    public static SignatureSubpackets refreshHashedSubpackets(PGPPublicKey issuer, PGPSignature oldSignature) {
        return createHashedSubpacketsFrom(issuer, oldSignature.getHashedSubPackets());
    }

    public static SignatureSubpackets refreshUnhashedSubpackets(PGPSignature oldSignature) {
        return createSubpacketsFrom(oldSignature.getUnhashedSubPackets());
    }

    public static SignatureSubpackets createHashedSubpacketsFrom(PGPPublicKey issuer, PGPSignatureSubpacketVector base) {
        SignatureSubpackets wrapper = createSubpacketsFrom(base);
        wrapper.setIssuerFingerprintAndKeyId(issuer);
        return wrapper;
    }

    public static SignatureSubpackets createSubpacketsFrom(PGPSignatureSubpacketVector base) {
        SignatureSubpackets wrapper = new SignatureSubpackets();
        SignatureSubpacketsHelper.applyFrom(base, wrapper);
        return wrapper;
    }

    public static SignatureSubpackets createHashedSubpackets(PGPPublicKey issuer) {
        SignatureSubpackets wrapper = new SignatureSubpackets();
        wrapper.setIssuerFingerprintAndKeyId(issuer);
        return wrapper;
    }

    public static SignatureSubpackets createEmptySubpackets() {
        return new SignatureSubpackets();
    }

    @Override
    public SignatureSubpackets setIssuerFingerprintAndKeyId(PGPPublicKey key) {
        setIssuerKeyId(key.getKeyID());
        setIssuerFingerprint(key);
        return this;
    }

    @Override
    public SignatureSubpackets setIssuerKeyId(long keyId) {
        return setIssuerKeyId(false, keyId);
    }

    @Override
    public SignatureSubpackets setIssuerKeyId(boolean isCritical, long keyId) {
        return setIssuerKeyId(new IssuerKeyID(isCritical, keyId));
    }

    @Override
    public SignatureSubpackets setIssuerKeyId(@Nullable IssuerKeyID issuerKeyID) {
        this.issuerKeyID = issuerKeyID;
        return this;
    }

    public IssuerKeyID getIssuerKeyIdSubpacket() {
        return issuerKeyID;
    }

    @Override
    public SignatureSubpackets setIssuerFingerprint(@Nonnull PGPPublicKey key) {
        return setIssuerFingerprint(false, key);
    }

    @Override
    public SignatureSubpackets setIssuerFingerprint(boolean isCritical, @Nonnull PGPPublicKey key) {
        return setIssuerFingerprint(new IssuerFingerprint(isCritical, key.getVersion(), key.getFingerprint()));
    }

    @Override
    public SignatureSubpackets setIssuerFingerprint(@Nullable IssuerFingerprint fingerprint) {
        this.issuerFingerprint = fingerprint;
        return this;
    }

    public IssuerFingerprint getIssuerFingerprintSubpacket() {
        return issuerFingerprint;
    }

    @Override
    public SignatureSubpackets setKeyFlags(KeyFlag... keyFlags) {
        return setKeyFlags(true, keyFlags);
    }

    @Override
    public SignatureSubpackets setKeyFlags(boolean isCritical, KeyFlag... keyFlags) {
        int bitmask = KeyFlag.toBitmask(keyFlags);
        return setKeyFlags(new KeyFlags(isCritical, bitmask));
    }

    @Override
    public SignatureSubpackets setKeyFlags(@Nullable KeyFlags keyFlags) {
        this.keyFlags = keyFlags;
        return this;
    }

    public KeyFlags getKeyFlagsSubpacket() {
        return keyFlags;
    }

    @Override
    public SignatureSubpackets setSignatureCreationTime(@Nonnull Date creationTime) {
        return setSignatureCreationTime(true, creationTime);
    }

    @Override
    public SignatureSubpackets setSignatureCreationTime(boolean isCritical, @Nonnull Date creationTime) {
        return setSignatureCreationTime(new SignatureCreationTime(isCritical, creationTime));
    }

    @Override
    public SignatureSubpackets setSignatureCreationTime(@Nullable SignatureCreationTime signatureCreationTime) {
        this.signatureCreationTime = signatureCreationTime;
        return this;
    }

    public SignatureCreationTime getSignatureCreationTimeSubpacket() {
        return signatureCreationTime;
    }

    @Override
    public SignatureSubpackets setSignatureExpirationTime(@Nonnull Date creationTime, @Nonnull Date expirationTime) {
        return setSignatureExpirationTime(true, creationTime, expirationTime);
    }

    @Override
    public SignatureSubpackets setSignatureExpirationTime(boolean isCritical, @Nonnull Date creationTime, @Nonnull Date expirationTime) {
        return setSignatureExpirationTime(isCritical, (expirationTime.getTime() / 1000) - (creationTime.getTime() / 1000));
    }

    @Override
    public SignatureSubpackets setSignatureExpirationTime(boolean isCritical, long seconds) {
        if (seconds < 0) {
            throw new IllegalArgumentException("Expiration time cannot be negative.");
        }
        return setSignatureExpirationTime(new SignatureExpirationTime(isCritical, seconds));
    }

    @Override
    public SignatureSubpackets setSignatureExpirationTime(@Nullable SignatureExpirationTime expirationTime) {
        this.signatureExpirationTime = expirationTime;
        return this;
    }

    public SignatureExpirationTime getSignatureExpirationTimeSubpacket() {
        return signatureExpirationTime;
    }

    @Override
    public SignatureSubpackets setSignerUserId(@Nonnull String userId) {
        return setSignerUserId(false, userId);
    }

    @Override
    public SignatureSubpackets setSignerUserId(boolean isCritical, @Nonnull String userId) {
        return setSignerUserId(new SignerUserID(isCritical, userId));
    }

    @Override
    public SignatureSubpackets setSignerUserId(@Nullable SignerUserID signerUserId) {
        this.signerUserId = signerUserId;
        return this;
    }

    public SignerUserID getSignerUserIdSubpacket() {
        return signerUserId;
    }

    @Override
    public SignatureSubpackets setPrimaryUserId() {
        return setPrimaryUserId(true);
    }

    @Override
    public SignatureSubpackets setPrimaryUserId(boolean isCritical) {
        return setPrimaryUserId(new PrimaryUserID(isCritical, true));
    }

    @Override
    public SignatureSubpackets setPrimaryUserId(@Nullable PrimaryUserID primaryUserId) {
        this.primaryUserId = primaryUserId;
        return this;
    }

    public PrimaryUserID getPrimaryUserIdSubpacket() {
        return primaryUserId;
    }

    @Override
    public SignatureSubpackets setKeyExpirationTime(@Nonnull PGPPublicKey key, @Nonnull Date keyExpirationTime) {
        return setKeyExpirationTime(key.getCreationTime(), keyExpirationTime);
    }

    @Override
    public SignatureSubpackets setKeyExpirationTime(@Nonnull Date keyCreationTime, @Nonnull Date keyExpirationTime) {
        return setKeyExpirationTime(true, keyCreationTime, keyExpirationTime);
    }

    @Override
    public SignatureSubpackets setKeyExpirationTime(boolean isCritical, @Nonnull Date keyCreationTime, @Nonnull Date keyExpirationTime) {
        return setKeyExpirationTime(isCritical, (keyExpirationTime.getTime() / 1000) - (keyCreationTime.getTime() / 1000));
    }

    @Override
    public SignatureSubpackets setKeyExpirationTime(boolean isCritical, long secondsFromCreationToExpiration) {
        if (secondsFromCreationToExpiration < 0) {
            throw new IllegalArgumentException("Seconds from key creation to expiration cannot be less than 0.");
        }
        return setKeyExpirationTime(new KeyExpirationTime(isCritical, secondsFromCreationToExpiration));
    }

    @Override
    public SignatureSubpackets setKeyExpirationTime(@Nullable KeyExpirationTime keyExpirationTime) {
        this.keyExpirationTime = keyExpirationTime;
        return this;
    }

    public KeyExpirationTime getKeyExpirationTimeSubpacket() {
        return keyExpirationTime;
    }

    @Override
    public SignatureSubpackets setPreferredCompressionAlgorithms(CompressionAlgorithm... algorithms) {
        return setPreferredCompressionAlgorithms(new LinkedHashSet<>(Arrays.asList(algorithms)));
    }

    @Override
    public SignatureSubpackets setPreferredCompressionAlgorithms(Set<CompressionAlgorithm> algorithms) {
        return setPreferredCompressionAlgorithms(false, algorithms);
    }

    @Override
    public SignatureSubpackets setPreferredCompressionAlgorithms(boolean isCritical, Set<CompressionAlgorithm> algorithms) {
        int[] ids = new int[algorithms.size()];
        Iterator<CompressionAlgorithm> iterator = algorithms.iterator();
        for (int i = 0; i < algorithms.size(); i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return setPreferredCompressionAlgorithms(new PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_COMP_ALGS, isCritical, ids));
    }

    @Override
    public SignatureSubpackets setPreferredCompressionAlgorithms(@Nullable PreferredAlgorithms algorithms) {
        if (algorithms == null) {
            this.preferredCompressionAlgorithms = null;
            return this;
        }

        if (algorithms.getType() != SignatureSubpacketTags.PREFERRED_COMP_ALGS) {
            throw new IllegalArgumentException("Invalid preferred compression algorithms type.");
        }
        this.preferredCompressionAlgorithms = algorithms;
        return this;
    }

    public PreferredAlgorithms getPreferredCompressionAlgorithmsSubpacket() {
        return preferredCompressionAlgorithms;
    }

    @Override
    public SignatureSubpackets setPreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm... algorithms) {
        return setPreferredSymmetricKeyAlgorithms(new LinkedHashSet<>(Arrays.asList(algorithms)));
    }

    @Override
    public SignatureSubpackets setPreferredSymmetricKeyAlgorithms(Set<SymmetricKeyAlgorithm> algorithms) {
        return setPreferredSymmetricKeyAlgorithms(false, algorithms);
    }

    @Override
    public SignatureSubpackets setPreferredSymmetricKeyAlgorithms(boolean isCritical, Set<SymmetricKeyAlgorithm> algorithms) {
        int[] ids = new int[algorithms.size()];
        Iterator<SymmetricKeyAlgorithm> iterator = algorithms.iterator();
        for (int i = 0; i < algorithms.size(); i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return setPreferredSymmetricKeyAlgorithms(new PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_SYM_ALGS, isCritical, ids));
    }

    @Override
    public SignatureSubpackets setPreferredSymmetricKeyAlgorithms(@Nullable PreferredAlgorithms algorithms) {
        if (algorithms == null) {
            this.preferredSymmetricKeyAlgorithms = null;
            return this;
        }

        if (algorithms.getType() != SignatureSubpacketTags.PREFERRED_SYM_ALGS) {
            throw new IllegalArgumentException("Invalid preferred symmetric key algorithms type.");
        }
        this.preferredSymmetricKeyAlgorithms = algorithms;
        return this;
    }

    public PreferredAlgorithms getPreferredSymmetricKeyAlgorithmsSubpacket() {
        return preferredSymmetricKeyAlgorithms;
    }

    @Override
    public SignatureSubpackets setPreferredHashAlgorithms(HashAlgorithm... algorithms) {
        return setPreferredHashAlgorithms(new LinkedHashSet<>(Arrays.asList(algorithms)));
    }

    @Override
    public SignatureSubpackets setPreferredHashAlgorithms(Set<HashAlgorithm> algorithms) {
        return setPreferredHashAlgorithms(false, algorithms);
    }

    @Override
    public SignatureSubpackets setPreferredHashAlgorithms(boolean isCritical, Set<HashAlgorithm> algorithms) {
        int[] ids = new int[algorithms.size()];
        Iterator<HashAlgorithm> iterator = algorithms.iterator();
        for (int i = 0; i < ids.length; i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return setPreferredHashAlgorithms(new PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_HASH_ALGS, isCritical, ids));
    }

    @Override
    public SignatureSubpackets setPreferredHashAlgorithms(@Nullable PreferredAlgorithms algorithms) {
        if (algorithms == null) {
            preferredHashAlgorithms = null;
            return this;
        }

        if (algorithms.getType() != SignatureSubpacketTags.PREFERRED_HASH_ALGS) {
            throw new IllegalArgumentException("Invalid preferred hash algorithms type.");
        }
        this.preferredHashAlgorithms = algorithms;
        return this;
    }

    public PreferredAlgorithms getPreferredHashAlgorithmsSubpacket() {
        return preferredHashAlgorithms;
    }

    @Override
    public SignatureSubpackets addNotationData(boolean isCritical, @Nonnull String notationName, @Nonnull String notationValue) {
        return addNotationData(isCritical, true, notationName, notationValue);
    }

    @Override
    public SignatureSubpackets addNotationData(boolean isCritical, boolean isHumanReadable, @Nonnull String notationName, @Nonnull String notationValue) {
        return addNotationData(new NotationData(isCritical, isHumanReadable, notationName, notationValue));
    }

    @Override
    public SignatureSubpackets addNotationData(@Nonnull NotationData notationData) {
        notationDataList.add(notationData);
        return this;
    }

    @Override
    public SignatureSubpackets clearNotationData() {
        notationDataList.clear();
        return this;
    }

    public List<NotationData> getNotationDataSubpackets() {
        return new ArrayList<>(notationDataList);
    }

    @Override
    public SignatureSubpackets addIntendedRecipientFingerprint(@Nonnull PGPPublicKey recipient) {
        return addIntendedRecipientFingerprint(false, recipient);
    }

    @Override
    public SignatureSubpackets addIntendedRecipientFingerprint(boolean isCritical, @Nonnull PGPPublicKey recipient) {
        return addIntendedRecipientFingerprint(new IntendedRecipientFingerprint(isCritical, recipient.getVersion(), recipient.getFingerprint()));
    }

    @Override
    public SignatureSubpackets addIntendedRecipientFingerprint(IntendedRecipientFingerprint intendedRecipientFingerprint) {
        this.intendedRecipientFingerprintList.add(intendedRecipientFingerprint);
        return this;
    }

    @Override
    public SignatureSubpackets clearIntendedRecipientFingerprints() {
        intendedRecipientFingerprintList.clear();
        return this;
    }

    public List<IntendedRecipientFingerprint> getIntendedRecipientFingerprintSubpackets() {
        return new ArrayList<>(intendedRecipientFingerprintList);
    }

    @Override
    public SignatureSubpackets setExportable(boolean exportable) {
        return setExportable(true, exportable);
    }

    @Override
    public SignatureSubpackets setExportable(boolean isCritical, boolean isExportable) {
        return setExportable(new Exportable(isCritical, isExportable));
    }

    @Override
    public SignatureSubpackets setExportable(@Nullable Exportable exportable) {
        this.exportable = exportable;
        return this;
    }

    public Exportable getExportableSubpacket() {
        return exportable;
    }

    @Override
    public SignatureSubpackets setRevocable(boolean revocable) {
        return setRevocable(true, revocable);
    }

    @Override
    public SignatureSubpackets setRevocable(boolean isCritical, boolean isRevocable) {
        return setRevocable(new Revocable(isCritical, isRevocable));
    }

    @Override
    public SignatureSubpackets setRevocable(@Nullable Revocable revocable) {
        this.revocable = revocable;
        return this;
    }

    public Revocable getRevocableSubpacket() {
        return revocable;
    }

    @Override
    public SignatureSubpackets addRevocationKey(@Nonnull PGPPublicKey revocationKey) {
        return addRevocationKey(true, revocationKey);
    }

    @Override
    public SignatureSubpackets addRevocationKey(boolean isCritical, @Nonnull PGPPublicKey revocationKey) {
        return addRevocationKey(isCritical, false, revocationKey);
    }

    @Override
    public SignatureSubpackets addRevocationKey(boolean isCritical, boolean isSensitive, @Nonnull PGPPublicKey revocationKey) {
        byte clazz = (byte) 0x80;
        clazz |= (isSensitive ? 0x40 : 0x00);
        return addRevocationKey(new RevocationKey(isCritical, clazz, revocationKey.getAlgorithm(), revocationKey.getFingerprint()));
    }

    @Override
    public SignatureSubpackets addRevocationKey(@Nonnull RevocationKey revocationKey) {
        this.revocationKeyList.add(revocationKey);
        return this;
    }

    @Override
    public SignatureSubpackets clearRevocationKeys() {
        revocationKeyList.clear();
        return this;
    }

    public List<RevocationKey> getRevocationKeySubpackets() {
        return new ArrayList<>(revocationKeyList);
    }

    @Override
    public SignatureSubpackets setRevocationReason(RevocationAttributes revocationAttributes) {
        return setRevocationReason(false, revocationAttributes);
    }

    @Override
    public SignatureSubpackets setRevocationReason(boolean isCritical, RevocationAttributes revocationAttributes) {
        return setRevocationReason(isCritical, revocationAttributes.getReason(), revocationAttributes.getDescription());
    }

    @Override
    public SignatureSubpackets setRevocationReason(boolean isCritical, RevocationAttributes.Reason reason, @Nonnull String description) {
        return setRevocationReason(new RevocationReason(isCritical, reason.code(), description));
    }

    @Override
    public SignatureSubpackets setRevocationReason(@Nullable RevocationReason reason) {
        this.revocationReason = reason;
        return this;
    }

    public RevocationReason getRevocationReasonSubpacket() {
        return revocationReason;
    }

    @Override
    public SignatureSubpackets setSignatureTarget(@Nonnull PublicKeyAlgorithm keyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData) {
        return setSignatureTarget(true, keyAlgorithm, hashAlgorithm, hashData);
    }

    @Override
    public SignatureSubpackets setSignatureTarget(boolean isCritical, @Nonnull PublicKeyAlgorithm keyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData) {
        return setSignatureTarget(new SignatureTarget(isCritical, keyAlgorithm.getAlgorithmId(), hashAlgorithm.getAlgorithmId(), hashData));
    }

    @Override
    public SignatureSubpackets setSignatureTarget(@Nullable SignatureTarget signatureTarget) {
        this.signatureTarget = signatureTarget;
        return this;
    }

    public SignatureTarget getSignatureTargetSubpacket() {
        return signatureTarget;
    }

    @Override
    public SignatureSubpackets setFeatures(Feature... features) {
        return setFeatures(true, features);
    }

    @Override
    public SignatureSubpackets setFeatures(boolean isCritical, Feature... features) {
        byte bitmask = Feature.toBitmask(features);
        return setFeatures(new Features(isCritical, bitmask));
    }

    @Override
    public SignatureSubpackets setFeatures(@Nullable Features features) {
        this.features = features;
        return this;
    }

    public Features getFeaturesSubpacket() {
        return features;
    }

    @Override
    public SignatureSubpackets setTrust(int depth, int amount) {
        return setTrust(true, depth, amount);
    }

    @Override
    public SignatureSubpackets setTrust(boolean isCritical, int depth, int amount) {
        return setTrust(new TrustSignature(isCritical, depth, amount));
    }

    @Override
    public SignatureSubpackets setTrust(@Nullable TrustSignature trust) {
        this.trust = trust;
        return this;
    }

    public TrustSignature getTrustSubpacket() {
        return trust;
    }

    @Override
    public SignatureSubpackets addEmbeddedSignature(@Nonnull PGPSignature signature) throws IOException {
        return addEmbeddedSignature(true, signature);
    }

    @Override
    public SignatureSubpackets addEmbeddedSignature(boolean isCritical, @Nonnull PGPSignature signature) throws IOException {
        byte[] sig = signature.getEncoded();
        byte[] data;

        if (sig.length - 1 > 256) {
            data = new byte[sig.length - 3];
        }
        else {
            data = new byte[sig.length - 2];
        }

        System.arraycopy(sig, sig.length - data.length, data, 0, data.length);

        return addEmbeddedSignature(new EmbeddedSignature(isCritical, false, data));
    }

    @Override
    public SignatureSubpackets addEmbeddedSignature(@Nonnull EmbeddedSignature embeddedSignature) {
        this.embeddedSignatureList.add(embeddedSignature);
        return this;
    }

    @Override
    public SignatureSubpackets clearEmbeddedSignatures() {
        this.embeddedSignatureList.clear();
        return this;
    }

    public List<EmbeddedSignature> getEmbeddedSignatureSubpackets() {
        return new ArrayList<>(embeddedSignatureList);
    }

    public SignatureSubpackets addResidualSubpacket(SignatureSubpacket subpacket) {
        this.residualSubpackets.add(subpacket);
        return this;
    }

    public List<SignatureSubpacket> getResidualSubpackets() {
        return new ArrayList<>(residualSubpackets);
    }

}
