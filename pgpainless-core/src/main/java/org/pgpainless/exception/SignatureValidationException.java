// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
