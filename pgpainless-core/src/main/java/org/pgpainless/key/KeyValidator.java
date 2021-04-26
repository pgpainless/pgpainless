/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.key;

import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.signature.SelectSignatureFromKey;

public class KeyValidator {

    public PGPPublicKeyRing validatePublicKeyRing(PGPPublicKeyRing publicKeys) throws PGPException {
        PGPPublicKey primaryKey = publicKeys.getPublicKey();
        if (!isValidPrimaryKey(primaryKey, publicKeys)) {
            throw new PGPException("Primary key is not valid");
        }
        return publicKeys;
    }

    public static boolean isValidPrimaryKey(PGPPublicKey publicKey, PGPPublicKeyRing keyRing) {
        if (!publicKey.isMasterKey()) {
            return false;
        }

        if (keyRing.getPublicKey().getKeyID() != publicKey.getKeyID()) {
            return false;
        }

        Iterator<PGPSignature> signatures = publicKey.getSignatures();
        while (signatures.hasNext()) {
            PGPSignature signature = signatures.next();
            SignatureType signatureType = SignatureType.valueOf(signature.getSignatureType());
            switch (signatureType) {
                case KEY_REVOCATION:
                    if (SelectSignatureFromKey.isValidKeyRevocationSignature(publicKey).accept(signature, publicKey, keyRing)) {
                        return false;
                    }
            }
        }
        return true;
    }
}
