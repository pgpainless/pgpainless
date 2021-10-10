// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import sop.ReadyWithResult;
import sop.Signatures;

public interface DetachInbandSignatureAndMessage {

    /**
     * Do not wrap the signatures in ASCII armor.
     * @return builder
     */
    DetachInbandSignatureAndMessage noArmor();

    /**
     * Detach the provided cleartext signed message from its signatures.
     *
     * @param messageInputStream input stream containing the signed message
     * @return result containing the detached message
     * @throws IOException in case of an IO error
     */
    ReadyWithResult<Signatures> message(InputStream messageInputStream) throws IOException;

    /**
     * Detach the provided cleartext signed message from its signatures.
     *
     * @param message byte array containing the signed message
     * @return result containing the detached message
     * @throws IOException in case of an IO error
     */
    default ReadyWithResult<Signatures> message(byte[] message) throws IOException {
        return message(new ByteArrayInputStream(message));
    }
}
