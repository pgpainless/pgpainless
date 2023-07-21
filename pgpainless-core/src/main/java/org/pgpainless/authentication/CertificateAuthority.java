// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.authentication;

import org.pgpainless.key.OpenPgpFingerprint;

import javax.annotation.Nonnull;
import java.util.Date;
import java.util.List;

public interface CertificateAuthority {

    /**
     * Determine the authenticity of the binding between the given fingerprint and the userId.
     * In other words, determine, how much evidence can be gathered, that the certificate with the given
     * fingerprint really belongs to the user with the given userId.
     *
     * @param fingerprint fingerprint of the certificate
     * @param userId userId
     * @param email if true, the userId will be treated as an email address and all user-IDs containing
     *             the email address will be matched.
     * @param referenceTime reference time at which the binding shall be evaluated
     * @param targetAmount target trust amount (120 = fully authenticated, 240 = doubly authenticated,
     *                    60 = partially authenticated...)
     * @return information about the authenticity of the binding
     */
    CertificateAuthenticity authenticate(@Nonnull OpenPgpFingerprint fingerprint,
                                         @Nonnull String userId,
                                         boolean email,
                                         @Nonnull Date referenceTime,
                                         int targetAmount);

    /**
     * Lookup certificates, which carry a trustworthy binding to the given userId.
     *
     * @param userId userId
     * @param email if true, the user-ID will be treated as an email address and all user-IDs containing
     *             the email address will be matched.
     * @param referenceTime reference time at which the binding shall be evaluated
     * @param targetAmount target trust amount (120 = fully authenticated, 240 = doubly authenticated,
     *                     60 = partially authenticated...)
     * @return list of identified bindings
     */
    List<CertificateAuthenticity> lookup(@Nonnull String userId,
                                         boolean email,
                                         @Nonnull Date referenceTime,
                                         int targetAmount);
}
