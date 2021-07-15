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
package sop.operation;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.exception.SOPGPException;

public interface Decrypt {

    /**
     * Makes the SOP consider signatures before this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Decrypt verifyNotBefore(Date timestamp)
            throws SOPGPException.UnsupportedOption;

    /**
     * Makes the SOP consider signatures after this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Decrypt verifyNotAfter(Date timestamp)
            throws SOPGPException.UnsupportedOption;

    /**
     * Adds the verification cert.
     *
     * @param cert input stream containing the cert
     * @return builder instance
     */
    Decrypt verifyWithCert(InputStream cert)
            throws SOPGPException.BadData,
            IOException;

    /**
     * Tries to decrypt with the given session key.
     *
     * @param sessionKey session key
     * @return builder instance
     */
    Decrypt withSessionKey(SessionKey sessionKey)
            throws SOPGPException.UnsupportedOption;

    /**
     * Tries to decrypt with the given password.
     *
     * @param password password
     * @return builder instance
     */
    Decrypt withPassword(String password)
            throws SOPGPException.PasswordNotHumanReadable,
            SOPGPException.UnsupportedOption;

    /**
     * Adds the decryption key.
     *
     * @param key input stream containing the key
     * @return builder instance
     */
    Decrypt withKey(InputStream key)
            throws SOPGPException.KeyIsProtected,
            SOPGPException.BadData,
            SOPGPException.UnsupportedAsymmetricAlgo;

    /**
     * Decrypts the given ciphertext, returning verification results and plaintext.
     * @param ciphertext ciphertext
     * @return ready with result
     */
    ReadyWithResult<DecryptionResult> ciphertext(InputStream ciphertext)
            throws SOPGPException.BadData, SOPGPException.MissingArg, SOPGPException.CannotDecrypt;
}
