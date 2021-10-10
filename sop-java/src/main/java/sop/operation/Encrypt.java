// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.ByteArrayInputStream;
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
     * Adds the signer key.
     *
     * @param key byte array containing the encoded signer key
     * @return builder instance
     */
    default Encrypt signWith(byte[] key)
            throws SOPGPException.KeyIsProtected,
            SOPGPException.CertCannotSign,
            SOPGPException.UnsupportedAsymmetricAlgo,
            SOPGPException.BadData {
        return signWith(new ByteArrayInputStream(key));
    }

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
     * Encrypt with the given cert.
     *
     * @param cert byte array containing the encoded cert.
     * @return builder instance
     */
    default Encrypt withCert(byte[] cert)
            throws SOPGPException.CertCannotEncrypt,
            SOPGPException.UnsupportedAsymmetricAlgo,
            SOPGPException.BadData {
        return withCert(new ByteArrayInputStream(cert));
    }

    /**
     * Encrypt the given data yielding the ciphertext.
     * @param plaintext plaintext
     * @return input stream containing the ciphertext
     */
    Ready plaintext(InputStream plaintext)
        throws IOException;

    /**
     * Encrypt the given data yielding the ciphertext.
     * @param plaintext plaintext
     * @return input stream containing the ciphertext
     */
    default Ready plaintext(byte[] plaintext) throws IOException {
        return plaintext(new ByteArrayInputStream(plaintext));
    }
}
