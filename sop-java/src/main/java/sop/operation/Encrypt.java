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

import sop.Ready;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;

public interface Encrypt {

    /**
     * Disable ASCII armor encoding.
     *
     * @return builder instance
     */
    Encrypt noArmor();

    /**
     * Sets encryption mode.
     *
     * @param mode mode
     * @return builder instance
     */
    Encrypt mode(EncryptAs mode)
            throws SOPGPException.UnsupportedOption;

    /**
     * Adds the signer key.
     *
     * @param key input stream containing the encoded signer key
     * @return builder instance
     */
    Encrypt signWith(InputStream key)
            throws SOPGPException.KeyIsProtected,
            SOPGPException.CertCannotSign,
            SOPGPException.UnsupportedAsymmetricAlgo,
            SOPGPException.BadData;

    /**
     * Encrypt with the given password.
     *
     * @param password password
     * @return builder instance
     */
    Encrypt withPassword(String password)
            throws SOPGPException.PasswordNotHumanReadable,
            SOPGPException.UnsupportedOption;

    /**
     * Encrypt with the given cert.
     *
     * @param cert input stream containing the encoded cert.
     * @return builder instance
     */
    Encrypt withCert(InputStream cert)
            throws SOPGPException.CertCannotEncrypt,
            SOPGPException.UnsupportedAsymmetricAlgo,
            SOPGPException.BadData;

    /**
     * Encrypt the given data yielding the ciphertext.
     * @param plaintext plaintext
     * @return input stream containing the ciphertext
     */
    Ready plaintext(InputStream plaintext)
        throws IOException;
}
