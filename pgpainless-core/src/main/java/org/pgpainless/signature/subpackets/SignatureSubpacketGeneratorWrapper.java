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
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.util.RevocationAttributes;

public class SignatureSubpacketGeneratorWrapper
        implements BaseSignatureSubpackets, SelfSignatureSubpackets, RevocationSignatureSubpackets {

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

    public SignatureSubpacketGeneratorWrapper() {
        setSignatureCreationTime(new Date());
    }

    public SignatureSubpacketGeneratorWrapper(PGPPublicKey issuer) {
        this();
        setIssuerFingerprintAndKeyId(issuer);
    }

    public PGPSignatureSubpacketGenerator getGenerator() {
        PGPSignatureSubpacketGenerator generator = new PGPSignatureSubpacketGenerator();

        addSubpacket(generator, issuerKeyID);
        addSubpacket(generator, issuerFingerprint);
        addSubpacket(generator, signatureCreationTime);
        addSubpacket(generator, signatureExpirationTime);
        addSubpacket(generator, exportable);
        for (NotationData notationData : notationDataList) {
            addSubpacket(generator, notationData);
        }
        for (IntendedRecipientFingerprint intendedRecipientFingerprint : intendedRecipientFingerprintList) {
            addSubpacket(generator, intendedRecipientFingerprint);
        }
        for (RevocationKey revocationKey : revocationKeyList) {
            addSubpacket(generator, revocationKey);
        }
        addSubpacket(generator, signatureTarget);
        addSubpacket(generator, features);
        addSubpacket(generator, keyFlags);
        addSubpacket(generator, trust);
        addSubpacket(generator, preferredCompressionAlgorithms);
        addSubpacket(generator, preferredSymmetricKeyAlgorithms);
        addSubpacket(generator, preferredHashAlgorithms);
        for (EmbeddedSignature embeddedSignature : embeddedSignatureList) {
            addSubpacket(generator, embeddedSignature);
        }
        addSubpacket(generator, signerUserId);
        addSubpacket(generator, keyExpirationTime);
        addSubpacket(generator, primaryUserId);
        addSubpacket(generator, revocable);
        addSubpacket(generator, revocationReason);

        return generator;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setIssuerFingerprintAndKeyId(PGPPublicKey key) {
        setIssuerKeyId(key.getKeyID());
        setIssuerFingerprint(key);
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setIssuerKeyId(long keyId) {
        return setIssuerKeyId(true, keyId);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setIssuerKeyId(boolean isCritical, long keyId) {
        return setIssuerKeyId(new IssuerKeyID(isCritical, keyId));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setIssuerKeyId(@Nullable IssuerKeyID issuerKeyID) {
        this.issuerKeyID = issuerKeyID;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setIssuerFingerprint(@Nonnull PGPPublicKey key) {
        return setIssuerFingerprint(true, key);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setIssuerFingerprint(boolean isCritical, @Nonnull PGPPublicKey key) {
        return setIssuerFingerprint(new IssuerFingerprint(isCritical, key.getVersion(), key.getFingerprint()));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setIssuerFingerprint(@Nullable IssuerFingerprint fingerprint) {
        this.issuerFingerprint = fingerprint;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setKeyFlags(KeyFlag... keyFlags) {
        return setKeyFlags(true, keyFlags);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setKeyFlags(boolean isCritical, KeyFlag... keyFlags) {
        int bitmask = KeyFlag.toBitmask(keyFlags);
        return setKeyFlags(new KeyFlags(isCritical, bitmask));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setKeyFlags(@Nullable KeyFlags keyFlags) {
        this.keyFlags = keyFlags;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureCreationTime(@Nonnull Date creationTime) {
        return setSignatureCreationTime(true, creationTime);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureCreationTime(boolean isCritical, @Nonnull Date creationTime) {
        return setSignatureCreationTime(new SignatureCreationTime(isCritical, creationTime));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureCreationTime(@Nullable SignatureCreationTime signatureCreationTime) {
        this.signatureCreationTime = signatureCreationTime;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureExpirationTime(@Nonnull Date creationTime, @Nonnull Date expirationTime) {
        return setSignatureExpirationTime(true, creationTime, expirationTime);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureExpirationTime(boolean isCritical, @Nonnull Date creationTime, @Nonnull Date expirationTime) {
        return setSignatureExpirationTime(isCritical, (expirationTime.getTime() / 1000) - (creationTime.getTime() / 1000));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureExpirationTime(boolean isCritical, long seconds) {
        if (seconds < 0) {
            throw new IllegalArgumentException("Expiration time cannot be negative.");
        }
        return setSignatureExpirationTime(new SignatureExpirationTime(isCritical, seconds));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureExpirationTime(@Nullable SignatureExpirationTime expirationTime) {
        this.signatureExpirationTime = expirationTime;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignerUserId(@Nonnull String userId) {
        return setSignerUserId(false, userId);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignerUserId(boolean isCritical, @Nonnull String userId) {
        return setSignerUserId(new SignerUserID(isCritical, userId));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignerUserId(@Nullable SignerUserID signerUserId) {
        this.signerUserId = signerUserId;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPrimaryUserId() {
        return setPrimaryUserId(true);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPrimaryUserId(boolean isCritical) {
        return setPrimaryUserId(new PrimaryUserID(isCritical, true));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPrimaryUserId(@Nullable PrimaryUserID primaryUserId) {
        this.primaryUserId = primaryUserId;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setKeyExpirationTime(@Nonnull PGPPublicKey key, @Nonnull Date keyExpirationTime) {
        return setKeyExpirationTime(key.getCreationTime(), keyExpirationTime);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setKeyExpirationTime(@Nonnull Date keyCreationTime, @Nonnull Date keyExpirationTime) {
        return setKeyExpirationTime(true, keyCreationTime, keyExpirationTime);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setKeyExpirationTime(boolean isCritical, @Nonnull Date keyCreationTime, @Nonnull Date keyExpirationTime) {
        return setKeyExpirationTime(isCritical, (keyExpirationTime.getTime() / 1000) - (keyCreationTime.getTime() / 1000));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setKeyExpirationTime(boolean isCritical, long secondsFromCreationToExpiration) {
        if (secondsFromCreationToExpiration < 0) {
            throw new IllegalArgumentException("Seconds from key creation to expiration cannot be less than 0.");
        }
        return setKeyExpirationTime(new KeyExpirationTime(isCritical, secondsFromCreationToExpiration));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setKeyExpirationTime(@Nullable KeyExpirationTime keyExpirationTime) {
        this.keyExpirationTime = keyExpirationTime;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredCompressionAlgorithms(CompressionAlgorithm... algorithms) {
        return setPreferredCompressionAlgorithms(new LinkedHashSet<>(Arrays.asList(algorithms)));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredCompressionAlgorithms(Set<CompressionAlgorithm> algorithms) {
        return setPreferredCompressionAlgorithms(true, algorithms);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredCompressionAlgorithms(boolean isCritical, Set<CompressionAlgorithm> algorithms) {
        int[] ids = new int[algorithms.size()];
        Iterator<CompressionAlgorithm> iterator = algorithms.iterator();
        for (int i = 0; i < algorithms.size(); i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return setPreferredCompressionAlgorithms(new PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_COMP_ALGS, isCritical, ids));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredCompressionAlgorithms(@Nullable PreferredAlgorithms algorithms) {
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

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm... algorithms) {
        return setPreferredSymmetricKeyAlgorithms(new LinkedHashSet<>(Arrays.asList(algorithms)));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredSymmetricKeyAlgorithms(Set<SymmetricKeyAlgorithm> algorithms) {
        return setPreferredSymmetricKeyAlgorithms(true, algorithms);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredSymmetricKeyAlgorithms(boolean isCritical, Set<SymmetricKeyAlgorithm> algorithms) {
        int[] ids = new int[algorithms.size()];
        Iterator<SymmetricKeyAlgorithm> iterator = algorithms.iterator();
        for (int i = 0; i < algorithms.size(); i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return setPreferredSymmetricKeyAlgorithms(new PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_SYM_ALGS, isCritical, ids));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredSymmetricKeyAlgorithms(@Nullable PreferredAlgorithms algorithms) {
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

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredHashAlgorithms(HashAlgorithm... algorithms) {
        return setPreferredHashAlgorithms(new LinkedHashSet<>(Arrays.asList(algorithms)));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredHashAlgorithms(Set<HashAlgorithm> algorithms) {
        return setPreferredHashAlgorithms(true, algorithms);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredHashAlgorithms(boolean isCritical, Set<HashAlgorithm> algorithms) {
        int[] ids = new int[algorithms.size()];
        Iterator<HashAlgorithm> iterator = algorithms.iterator();
        for (int i = 0; i < ids.length; i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return setPreferredHashAlgorithms(new PreferredAlgorithms(
                SignatureSubpacketTags.PREFERRED_HASH_ALGS, isCritical, ids));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setPreferredHashAlgorithms(@Nullable PreferredAlgorithms algorithms) {
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

    @Override
    public SignatureSubpacketGeneratorWrapper addNotationData(boolean isCritical, @Nonnull String notationName, @Nonnull String notationValue) {
        return addNotationData(new NotationData(isCritical, true, notationName, notationValue));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addNotationData(@Nonnull NotationData notationData) {
        notationDataList.add(notationData);
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper clearNotationData() {
        notationDataList.clear();
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addIntendedRecipientFingerprint(@Nonnull PGPPublicKey recipient) {
        return addIntendedRecipientFingerprint(false, recipient);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addIntendedRecipientFingerprint(boolean isCritical, @Nonnull PGPPublicKey recipient) {
        return addIntendedRecipientFingerprint(new IntendedRecipientFingerprint(isCritical, recipient.getVersion(), recipient.getFingerprint()));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addIntendedRecipientFingerprint(IntendedRecipientFingerprint intendedRecipientFingerprint) {
        this.intendedRecipientFingerprintList.add(intendedRecipientFingerprint);
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper clearIntendedRecipientFingerprints() {
        intendedRecipientFingerprintList.clear();
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setExportable(boolean isCritical, boolean isExportable) {
        return setExportable(new Exportable(isCritical, isExportable));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setExportable(@Nullable Exportable exportable) {
        this.exportable = exportable;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setRevocable(boolean isCritical, boolean isRevocable) {
        return setRevocable(new Revocable(isCritical, isRevocable));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setRevocable(@Nullable Revocable revocable) {
        this.revocable = revocable;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addRevocationKey(@Nonnull PGPPublicKey revocationKey) {
        return addRevocationKey(true, revocationKey);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addRevocationKey(boolean isCritical, @Nonnull PGPPublicKey revocationKey) {
        return addRevocationKey(isCritical, false, revocationKey);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addRevocationKey(boolean isCritical, boolean isSensitive, @Nonnull PGPPublicKey revocationKey) {
        byte clazz = (byte) 0x80;
        clazz |= (isSensitive ? 0x40 : 0x00);
        return addRevocationKey(new RevocationKey(isCritical, clazz, revocationKey.getAlgorithm(), revocationKey.getFingerprint()));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addRevocationKey(@Nonnull RevocationKey revocationKey) {
        this.revocationKeyList.add(revocationKey);
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper clearRevocationKeys() {
        revocationKeyList.clear();
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setRevocationReason(RevocationAttributes revocationAttributes) {
        return setRevocationReason(true, revocationAttributes);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setRevocationReason(boolean isCritical, RevocationAttributes revocationAttributes) {
        return setRevocationReason(isCritical, revocationAttributes.getReason(), revocationAttributes.getDescription());
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setRevocationReason(boolean isCritical, RevocationAttributes.Reason reason, @Nonnull String description) {
        return setRevocationReason(new RevocationReason(isCritical, reason.code(), description));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setRevocationReason(@Nullable RevocationReason reason) {
        this.revocationReason = reason;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureTarget(@Nonnull PublicKeyAlgorithm keyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData) {
        return setSignatureTarget(true, keyAlgorithm, hashAlgorithm, hashData);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureTarget(boolean isCritical, @Nonnull PublicKeyAlgorithm keyAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, @Nonnull byte[] hashData) {
        return setSignatureTarget(new SignatureTarget(isCritical, keyAlgorithm.getAlgorithmId(), hashAlgorithm.getAlgorithmId(), hashData));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setSignatureTarget(@Nullable SignatureTarget signatureTarget) {
        this.signatureTarget = signatureTarget;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setFeatures(Feature... features) {
        return setFeatures(true, features);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setFeatures(boolean isCritical, Feature... features) {
        byte bitmask = Feature.toBitmask(features);
        return setFeatures(new Features(isCritical, bitmask));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setFeatures(@Nullable Features features) {
        this.features = features;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setTrust(int depth, int amount) {
        return setTrust(true, depth, amount);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setTrust(boolean isCritical, int depth, int amount) {
        return setTrust(new TrustSignature(isCritical, depth, amount));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper setTrust(@Nullable TrustSignature trust) {
        this.trust = trust;
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addEmbeddedSignature(@Nonnull PGPSignature signature) throws IOException {
        return addEmbeddedSignature(true, signature);
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addEmbeddedSignature(boolean isCritical, @Nonnull PGPSignature signature) throws IOException {
        byte[] sig = signature.getEncoded();
        byte[] data;

        if (sig.length - 1 > 256)
        {
            data = new byte[sig.length - 3];
        }
        else
        {
            data = new byte[sig.length - 2];
        }

        System.arraycopy(sig, sig.length - data.length, data, 0, data.length);

        return addEmbeddedSignature(new EmbeddedSignature(isCritical, false, data));
    }

    @Override
    public SignatureSubpacketGeneratorWrapper addEmbeddedSignature(@Nonnull EmbeddedSignature embeddedSignature) {
        this.embeddedSignatureList.add(embeddedSignature);
        return this;
    }

    @Override
    public SignatureSubpacketGeneratorWrapper clearEmbeddedSignatures() {
        this.embeddedSignatureList.clear();
        return this;
    }

    private static void addSubpacket(PGPSignatureSubpacketGenerator generator, SignatureSubpacket subpacket) {
        if (subpacket != null) {
            generator.addCustomSubpacket(subpacket);
        }
    }
}
