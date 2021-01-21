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

public class OpenPgpKeyAttributeUtil {

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
