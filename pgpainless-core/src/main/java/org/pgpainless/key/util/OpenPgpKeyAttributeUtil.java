// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;

public final class OpenPgpKeyAttributeUtil {

    private OpenPgpKeyAttributeUtil() {

    }

    public static List<HashAlgorithm> getPreferredHashAlgorithms(PGPPublicKey publicKey) {
        List<HashAlgorithm> hashAlgorithms = new ArrayList<>();
        // TODO: I'd assume that we have to use publicKey.getKeySignatures() here, but that is empty...
        Iterator<?> keySignatures = publicKey.getSignatures();
        while (keySignatures.hasNext()) {
            PGPSignature signature = (PGPSignature) keySignatures.next();

            if (signature.getKeyID() != publicKey.getKeyID()) {
                // Signature from a foreign key. Skip.
                continue;
            }

            SignatureType signatureType = SignatureType.valueOf(signature.getSignatureType());
            if (signatureType == SignatureType.POSITIVE_CERTIFICATION
                    || signatureType == SignatureType.GENERIC_CERTIFICATION) {
                int[] hashAlgos = signature.getHashedSubPackets().getPreferredHashAlgorithms();
                if (hashAlgos == null) {
                    continue;
                }
                for (int h : hashAlgos) {
                    hashAlgorithms.add(HashAlgorithm.fromId(h));
                }
                // Exit the loop after the first key signature with hash algorithms.
                // TODO: Find out, if it is possible that there are multiple key signatures which specify preferred
                //  algorithms and how to deal with that.
                break;
            }
        }
        return hashAlgorithms;
    }

    /**
     * Return the hash algorithm that was used in the latest self signature.
     *
     * @param publicKey public key
     * @return list of hash algorithm
     */
    public static List<HashAlgorithm> guessPreferredHashAlgorithms(PGPPublicKey publicKey) {
        HashAlgorithm hashAlgorithm = null;
        Date lastCreationDate = null;

        Iterator<?> keySignatures = publicKey.getSignatures();
        while (keySignatures.hasNext()) {
            PGPSignature signature = (PGPSignature) keySignatures.next();
            if (signature.getKeyID() != publicKey.getKeyID()) {
                continue;
            }

            SignatureType signatureType = SignatureType.valueOf(signature.getSignatureType());
            if (signatureType != SignatureType.POSITIVE_CERTIFICATION
                    && signatureType != SignatureType.GENERIC_CERTIFICATION) {
                continue;
            }

            Date creationDate = signature.getCreationTime();
            if (lastCreationDate == null || lastCreationDate.before(creationDate)) {
                lastCreationDate = creationDate;
                hashAlgorithm = HashAlgorithm.fromId(signature.getHashAlgorithm());
            }
        }

        if (hashAlgorithm == null) {
            return Collections.emptyList();
        }
        return Collections.singletonList(hashAlgorithm);
    }
}
