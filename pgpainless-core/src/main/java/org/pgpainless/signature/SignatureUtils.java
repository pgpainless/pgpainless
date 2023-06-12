// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.util.ArmorUtils;

/**
 * Utility methods related to signatures.
 */
public final class SignatureUtils {

    public static final int MAX_ITERATIONS = 10000;

    private SignatureUtils() {

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
     * Since '0' is a special date value in the OpenPGP specification
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
     *
     * @throws IOException if the signatures cannot be read
     * @throws PGPException in case of a broken signature
     */
    public static List<PGPSignature> readSignatures(String encodedSignatures) throws IOException, PGPException {
        @SuppressWarnings("CharsetObjectCanBeUsed")
        Charset utf8 = Charset.forName("UTF-8");
        byte[] bytes = encodedSignatures.getBytes(utf8);
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
        return readSignatures(inputStream, MAX_ITERATIONS);
    }

    /**
     * Read and return {@link PGPSignature PGPSignatures}.
     * This method can deal with signatures that may be binary, armored and may contain marker packets.
     *
     * @param inputStream input stream
     * @param maxIterations number of loop iterations until reading is aborted
     * @return list of encountered signatures
     * @throws IOException in case of a stream error
     */
    public static List<PGPSignature> readSignatures(InputStream inputStream, int maxIterations) throws IOException {
        List<PGPSignature> signatures = new ArrayList<>();
        InputStream pgpIn = ArmorUtils.getDecoderStream(inputStream);
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(pgpIn);

        int i = 0;
        Object nextObject;
        while (i++ < maxIterations && (nextObject = objectFactory.nextObject()) != null) {

            // Since signatures are indistinguishable from randomness, there is no point in having them compressed,
            //  except for an attacker who is trying to exploit flaws in the decompression algorithm.
            //  Therefore, we ignore compressed data packets without attempting decompression.
            if (nextObject instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) nextObject;
                // getInputStream() does not do decompression, contrary to getDataStream().
                Streams.drain(compressedData.getInputStream()); // Skip packet without decompressing
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
        }
        pgpIn.close();

        return signatures;
    }

    /**
     * Determine the issuer key-id of a {@link PGPSignature}.
     * This method first inspects the {@link IssuerKeyID} subpacket of the signature and returns the key-id if present.
     * If not, it inspects the {@link org.bouncycastle.bcpg.sig.IssuerFingerprint} packet and retrieves the key-id from the fingerprint.
     *
     * Otherwise, it returns 0.
     * @param signature signature
     * @return signatures issuing key id
     */
    public static long determineIssuerKeyId(PGPSignature signature) {
        if (signature.getVersion() == 3) {
            // V3 sigs do not contain subpackets
            return signature.getKeyID();
        }

        IssuerKeyID issuerKeyId = SignatureSubpacketsUtil.getIssuerKeyId(signature);
        OpenPgpFingerprint fingerprint = SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpFingerprint(signature);

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

    public static boolean wasIssuedBy(byte[] fingerprint, PGPSignature signature) {
        try {
            OpenPgpFingerprint fp = OpenPgpFingerprint.parseFromBinary(fingerprint);
            OpenPgpFingerprint issuerFp = SignatureSubpacketsUtil.getIssuerFingerprintAsOpenPgpFingerprint(signature);
            if (issuerFp == null) {
                return fp.getKeyId() == signature.getKeyID();
            }
            return fp.equals(issuerFp);
        } catch (IllegalArgumentException e) {
            // Unknown fingerprint length
            return false;
        }
    }

    /**
     * Extract all signatures from the given <pre>key</pre> which were issued by <pre>issuerKeyId</pre>
     * over <pre>userId</pre>.
     *
     * @param key public key
     * @param userId user-id
     * @param issuerKeyId issuer key-id
     * @return (potentially empty) list of signatures
     */
    public static @Nonnull List<PGPSignature> getSignaturesOverUserIdBy(
            @Nonnull PGPPublicKey key,
            @Nonnull String userId,
            long issuerKeyId) {
        List<PGPSignature> signaturesByKeyId = new ArrayList<>();
        Iterator<PGPSignature> userIdSignatures = key.getSignaturesForID(userId);

        // getSignaturesForID() is nullable for some reason -.-
        if (userIdSignatures == null) {
            return signaturesByKeyId;
        }

        // filter for signatures by key-id
        while (userIdSignatures.hasNext()) {
            PGPSignature signature = userIdSignatures.next();
            if (signature.getKeyID() == issuerKeyId) {
                signaturesByKeyId.add(signature);
            }
        }

        return Collections.unmodifiableList(signaturesByKeyId);
    }
}
