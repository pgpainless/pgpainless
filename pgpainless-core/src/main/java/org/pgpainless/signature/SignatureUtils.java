/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.signature;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.util.OpenPgpKeyAttributeUtil;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.ArmorUtils;

/**
 * Utility methods related to signatures.
 */
public final class SignatureUtils {

    private SignatureUtils() {

    }

    /**
     * Return a signature generator for the provided signing key.
     * The signature generator will follow the hash algorithm preferences of the signing key and pick the best algorithm.
     *
     * @param singingKey signing key
     * @return signature generator
     */
    public static PGPSignatureGenerator getSignatureGeneratorFor(PGPSecretKey singingKey) {
        return getSignatureGeneratorFor(singingKey.getPublicKey());
    }

    /**
     * Return a signature generator for the provided signing key.
     * The signature generator will follow the hash algorithm preferences of the signing key and pick the best algorithm.
     *
     * @param signingPubKey signing key
     * @return signature generator
     */
    public static PGPSignatureGenerator getSignatureGeneratorFor(PGPPublicKey signingPubKey) {
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                getPgpContentSignerBuilderForKey(signingPubKey));
        return signatureGenerator;
    }

    /**
     * Return a content signer builder for the passed public key.
     *
     * The content signer will use a hash algorithm derived from the keys algorithm preferences.
     * If no preferences can be derived, the key will fall back to the default hash algorithm as set in
     * the {@link org.pgpainless.policy.Policy}.
     *
     * TODO: Move negotiation to negotiator class
     *
     * @param publicKey public key
     * @return content signer builder
     */
    private static PGPContentSignerBuilder getPgpContentSignerBuilderForKey(PGPPublicKey publicKey) {
        List<HashAlgorithm> preferredHashAlgorithms = OpenPgpKeyAttributeUtil.getPreferredHashAlgorithms(publicKey);
        if (preferredHashAlgorithms.isEmpty()) {
            preferredHashAlgorithms = OpenPgpKeyAttributeUtil.guessPreferredHashAlgorithms(publicKey);
        }
        HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(preferredHashAlgorithms);

        return ImplementationFactory.getInstance().getPGPContentSignerBuilder(publicKey.getAlgorithm(), hashAlgorithm.getAlgorithmId());
    }

    /**
     * Negotiate an acceptable hash algorithm from the provided list of options.
     * Acceptance of hash algorithms can be changed by setting a custom {@link Policy}.
     *
     * @param preferredHashAlgorithms list of preferred hash algorithms of a key
     * @return first acceptable algorithm, or policies default hash algorithm
     */
    private static HashAlgorithm negotiateHashAlgorithm(List<HashAlgorithm> preferredHashAlgorithms) {
        Policy policy = PGPainless.getPolicy();
        for (HashAlgorithm option : preferredHashAlgorithms) {
            if (policy.getSignatureHashAlgorithmPolicy().isAcceptable(option)) {
                return option;
            }
        }

        return PGPainless.getPolicy().getSignatureHashAlgorithmPolicy().defaultHashAlgorithm();
    }

    /**
     * Extract and return the key expiration date value from the given signature.
     * If the signature does not carry a {@link KeyExpirationTime} subpacket, return null.
     *
     * @param keyCreationDate creation date of the key
     * @param signature signature
     * @return key expiration date as given by the signature
     */
    public static Date getKeyExpirationDate(Date keyCreationDate, PGPSignature signature) {
        KeyExpirationTime keyExpirationTime = SignatureSubpacketsUtil.getKeyExpirationTime(signature);
        long expiresInSecs = keyExpirationTime == null ? 0 : keyExpirationTime.getTime();
        return datePlusSeconds(keyCreationDate, expiresInSecs);
    }

    /**
     * Return the expiration date of the signature.
     * If the signature has no expiration date, {@link #datePlusSeconds(Date, long)} will return null.
     *
     * @param signature signature
     * @return expiration date of the signature, or null if it does not expire.
     */
    public static Date getSignatureExpirationDate(PGPSignature signature) {
        Date creationDate = signature.getCreationTime();
        SignatureExpirationTime signatureExpirationTime = SignatureSubpacketsUtil.getSignatureExpirationTime(signature);
        long expiresInSecs = signatureExpirationTime == null ? 0 : signatureExpirationTime.getTime();
        return datePlusSeconds(creationDate, expiresInSecs);
    }

    /**
     * Return a new date which represents the given date plus the given amount of seconds added.
     *
     * Since '0' is a special value in the OpenPGP specification when it comes to dates
     * (e.g. '0' means no expiration for expiration dates), this method will return 'null' if seconds is 0.
     *
     * @param date date
     * @param seconds number of seconds to be added
     * @return date plus seconds or null if seconds is '0'
     */
    public static Date datePlusSeconds(Date date, long seconds) {
        if (seconds == 0) {
            return null;
        }
        return new Date(date.getTime() + 1000 * seconds);
    }

    /**
     * Return true, if the expiration date of the {@link PGPSignature} lays in the past.
     * If no expiration date is present in the signature, it is considered non-expired.
     *
     * @param signature signature
     * @return true if expired, false otherwise
     */
    public static boolean isSignatureExpired(PGPSignature signature) {
        return isSignatureExpired(signature, new Date());
    }

    /**
     * Return true, if the expiration date of the given {@link PGPSignature} is past the given comparison {@link Date}.
     * If no expiration date is present in the signature, it is considered non-expiring.
     *
     * @param signature signature
     * @param comparisonDate reference date
     * @return true if sig is expired at reference date, false otherwise
     */
    public static boolean isSignatureExpired(PGPSignature signature, Date comparisonDate) {
        Date expirationDate = getSignatureExpirationDate(signature);
        return expirationDate != null && comparisonDate.after(expirationDate);
    }

    /**
     * Return true if the provided signature is a hard revocation.
     * Hard revocations are revocation signatures which either carry a revocation reason of
     * {@link RevocationAttributes.Reason#KEY_COMPROMISED} or {@link RevocationAttributes.Reason#NO_REASON},
     * or no reason at all.
     *
     * @param signature signature
     * @return true if signature is a hard revocation
     */
    public static boolean isHardRevocation(PGPSignature signature) {

        SignatureType type = SignatureType.valueOf(signature.getSignatureType());
        if (type != SignatureType.KEY_REVOCATION && type != SignatureType.SUBKEY_REVOCATION && type != SignatureType.CERTIFICATION_REVOCATION) {
            // Not a revocation
            return false;
        }

        RevocationReason reasonSubpacket = SignatureSubpacketsUtil.getRevocationReason(signature);
        if (reasonSubpacket == null) {
            // no reason -> hard revocation
            return true;
        }
        return RevocationAttributes.Reason.isHardRevocation(reasonSubpacket.getRevocationReason());
    }

    /**
     * Parse an ASCII encoded list of OpenPGP signatures into a {@link PGPSignatureList}
     * and return it as a {@link List}.
     *
     * @param encodedSignatures ASCII armored signature list
     * @return signature list
     * @throws IOException if the signatures cannot be read
     */
    public static List<PGPSignature> readSignatures(String encodedSignatures) throws IOException, PGPException {
        byte[] bytes = encodedSignatures.getBytes(Charset.forName("UTF8"));
        return readSignatures(bytes);
    }

    /**
     * Read a single, or a list of {@link PGPSignature PGPSignatures} and return them as a {@link List}.
     *
     * @param encodedSignatures ASCII armored or binary signatures
     * @return signatures
     * @throws IOException if the signatures cannot be read
     * @throws PGPException in case of an OpenPGP error
     */
    public static List<PGPSignature> readSignatures(byte[] encodedSignatures) throws IOException, PGPException {
        InputStream inputStream = new ByteArrayInputStream(encodedSignatures);
        return readSignatures(inputStream);
    }

    /**
     * Read and return {@link PGPSignature PGPSignatures}.
     * This method can deal with signatures that may be armored, compressed and may contain marker packets.
     *
     * @param inputStream input stream
     * @return list of encountered signatures
     * @throws IOException in case of a stream error
     * @throws PGPException in case of an OpenPGP error
     */
    public static List<PGPSignature> readSignatures(InputStream inputStream) throws IOException, PGPException {
        List<PGPSignature> signatures = new ArrayList<>();
        InputStream pgpIn = ArmorUtils.getDecoderStream(inputStream);
        PGPObjectFactory objectFactory = new PGPObjectFactory(
                pgpIn, ImplementationFactory.getInstance().getKeyFingerprintCalculator());

        Object nextObject = tryNext(objectFactory);
        while (nextObject != null) {
            if (nextObject instanceof PGPMarker) {
                nextObject = tryNext(objectFactory);
                continue;
            }
            if (nextObject instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) nextObject;
                objectFactory = new PGPObjectFactory(compressedData.getDataStream(),
                        ImplementationFactory.getInstance().getKeyFingerprintCalculator());
                nextObject = tryNext(objectFactory);
                continue;
            }
            if (nextObject instanceof PGPSignatureList) {
                PGPSignatureList signatureList = (PGPSignatureList) nextObject;
                for (PGPSignature s : signatureList) {
                    signatures.add(s);
                }
            }
            if (nextObject instanceof PGPSignature) {
                signatures.add((PGPSignature) nextObject);
            }
            nextObject = tryNext(objectFactory);
        }
        pgpIn.close();

        return signatures;
    }

    /**
     * Try reading the next signature from the factory.
     *
     * This is a helper method for BC choking on unexpected data like invalid signature versions.
     * Unfortunately, this solves only half the issue, see bcgit/bc-java#1006 for a proper fix.
     *
     * @see <a href="https://github.com/bcgit/bc-java/pull/1006">BC-Java: Ignore PGPSignature with invalid version</a>
     *
     * @param factory pgp object factory
     * @return next non-throwing object or null
     * @throws IOException in case of a stream error
     */
    private static Object tryNext(PGPObjectFactory factory) throws IOException {
        try {
            Object o = factory.nextObject();
            return o;
        } catch (RuntimeException e) {
            return tryNext(factory);
        }
    }

    /**
     * Determine the issuer key-id of a {@link PGPSignature}.
     * This method first inspects the {@link IssuerKeyID} subpacket of the signature and returns the key-id if present.
     * If not, it inspects the {@link org.bouncycastle.bcpg.sig.IssuerFingerprint} packet and retrieves the key-id from the fingerprint.
     *
     * Otherwise it returns 0.
     * @param signature signature
     * @return signatures issuing key id
     */
    public static long determineIssuerKeyId(PGPSignature signature) {
        IssuerKeyID issuerKeyId = SignatureSubpacketsUtil.getIssuerKeyId(signature);
        OpenPgpV4Fingerprint fingerprint = SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpV4Fingerprint(signature);
        if (issuerKeyId != null && issuerKeyId.getKeyID() != 0) {
            return issuerKeyId.getKeyID();
        }
        if (issuerKeyId == null && fingerprint != null) {
            return fingerprint.getKeyId();
        }
        return 0;
    }

    /**
     * Return the digest prefix of the signature as hex-encoded String.
     *
     * @param signature signature
     * @return digest prefix
     */
    public static String getSignatureDigestPrefix(PGPSignature signature) {
        return Hex.toHexString(signature.getDigestPrefix());
    }

    public static List<PGPSignature> toList(PGPSignatureList signatures) {
        List<PGPSignature> list = new ArrayList<>();
        for (PGPSignature signature : signatures) {
            list.add(signature);
        }
        return list;
    }
}
