// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.InputStream
import java.util.*
import openpgp.anyOrElse
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.PGPainless
import sop.exception.SOPGPException
import sop.operation.ValidateUserId

class ValidateUserIdImpl(private val api: PGPainless) : ValidateUserId {

    private var addSpecOnly = false
    private var userId: String? = null
    private val authorities: MutableList<OpenPGPCertificate> = mutableListOf()
    private var validateAt: Date = Date()

    override fun addrSpecOnly(): ValidateUserId = apply { addSpecOnly = true }

    override fun authorities(certs: InputStream): ValidateUserId = apply {
        authorities.addAll(api.readKey().parseCertificates(certs))
    }

    override fun subjects(certs: InputStream): Boolean {
        requireNotNull(userId) { "Missing parameter USERID" }

        return api.readKey().parseCertificates(certs).all { cert ->
            val matchingUserIds =
                cert.allUserIds
                    .filter {
                        if (addSpecOnly) it.userId.contains("<$userId>")
                        else it.userId.equals(userId)
                    }
                    .ifEmpty {
                        throw SOPGPException.CertUserIdNoMatch(
                            "${cert.keyIdentifier} does not carry user-id ${if (addSpecOnly) "containing '<$userId>'" else "'${userId}'"}")
                    }

            // Succeed if and only if all OpenPGP certificates on standard input (certs)
            // are correctly bound by at least one valid signature from one authority
            // to the USERID in question.
            matchingUserIds.anyOrElse({ match ->
                authorities.any { authority ->
                    match.getCertificationBy(authority, validateAt)?.isValid ?: false
                }
            }) {
                throw SOPGPException.CertUserIdNoMatch(
                    "${cert.keyIdentifier} does not carry certification by any authority for user-ids ${matchingUserIds.joinToString()} at $validateAt")
            }
        }
    }

    override fun userId(userId: String): ValidateUserId = apply { this.userId = userId }

    override fun validateAt(date: Date): ValidateUserId = apply { validateAt = date }
}
