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

import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.pgpainless.algorithm.HashAlgorithm;

public class SignatureUtils {

    public static PGPSignatureGenerator getSignatureGeneratorFor(PGPSecretKey singingKey) {
        return getSignatureGeneratorFor(singingKey.getPublicKey());
    }

    public static PGPSignatureGenerator getSignatureGeneratorFor(PGPPublicKey signingPubKey) {
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                getPgpContentSignerBuilderForKey(signingPubKey));
        return signatureGenerator;
    }

    private static BcPGPContentSignerBuilder getPgpContentSignerBuilderForKey(PGPPublicKey publicKey) {
        List<HashAlgorithm> preferredHashAlgorithms = OpenPgpKeyAttributeUtil.getPreferredHashAlgorithms(publicKey);
        HashAlgorithm hashAlgorithm = negotiateHashAlgorithm(preferredHashAlgorithms);

        return new BcPGPContentSignerBuilder(publicKey.getAlgorithm(), hashAlgorithm.getAlgorithmId());
    }

    private static HashAlgorithm negotiateHashAlgorithm(List<HashAlgorithm> preferredHashAlgorithms) {
        // TODO: Match our list of supported hash algorithms against the list, to determine the best suitable algo.
        //  For now we just take the first algorithm in the list and hope that BC has support for it.
        return preferredHashAlgorithms.get(0);
    }
}
