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
package org.pgpainless.exception;

import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.SignatureType;

public class SignatureValidationException extends PGPException {

    public SignatureValidationException(String message) {
        super(message);
    }

    public SignatureValidationException(String message, Exception underlying) {
        super(message, underlying);
    }

    public SignatureValidationException(String message, Map<PGPSignature, Exception> rejections) {
        super(message + ": " + exceptionMapToString(rejections));
    }

    private static String exceptionMapToString(Map<PGPSignature, Exception> rejections) {
        StringBuilder sb = new StringBuilder();
        sb.append(rejections.size()).append(" rejected signatures:\n");
        for (PGPSignature signature : rejections.keySet()) {
            sb.append(SignatureType.valueOf(signature.getSignatureType())).append(' ')
                    .append(signature.getCreationTime()).append(": ")
                    .append(rejections.get(signature).getMessage()).append('\n');
        }
        return sb.toString();
    }
}
