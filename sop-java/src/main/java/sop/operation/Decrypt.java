// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.ByteArrayInputStream;
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
     * Adds the verification cert.
     *
     * @param cert byte array containing the cert
     * @return builder instance
     */
    default Decrypt verifyWithCert(byte[] cert)
            throws SOPGPException.BadData, IOException {
        return verifyWithCert(new ByteArrayInputStream(cert));
    }

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
     * Adds the decryption key.
     *
     * @param key byte array containing the key
     * @return builder instance
     */
    default Decrypt withKey(byte[] key)
            throws SOPGPException.KeyIsProtected,
            SOPGPException.BadData,
            SOPGPException.UnsupportedAsymmetricAlgo {
        return withKey(new ByteArrayInputStream(key));
    }

    /**
     * Decrypts the given ciphertext, returning verification results and plaintext.
     * @param ciphertext ciphertext
     * @return ready with result
     */
    ReadyWithResult<DecryptionResult> ciphertext(InputStream ciphertext)
            throws SOPGPException.BadData, SOPGPException.MissingArg, SOPGPException.CannotDecrypt;

    /**
     * Decrypts the given ciphertext, returning verification results and plaintext.
     * @param ciphertext ciphertext
     * @return ready with result
     */
    default ReadyWithResult<DecryptionResult> ciphertext(byte[] ciphertext)
        throws SOPGPException.BadData, SOPGPException.MissingArg, SOPGPException.CannotDecrypt {
        return ciphertext(new ByteArrayInputStream(ciphertext));
    }
}
