// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import org.pgpainless.PGPainless
import sop.SOP
import sop.SOPV
import sop.operation.Armor
import sop.operation.CertifyUserId
import sop.operation.ChangeKeyPassword
import sop.operation.Dearmor
import sop.operation.Decrypt
import sop.operation.DetachedSign
import sop.operation.DetachedVerify
import sop.operation.Encrypt
import sop.operation.ExtractCert
import sop.operation.GenerateKey
import sop.operation.InlineDetach
import sop.operation.InlineSign
import sop.operation.InlineVerify
import sop.operation.ListProfiles
import sop.operation.MergeCerts
import sop.operation.RevokeKey
import sop.operation.UpdateKey
import sop.operation.ValidateUserId
import sop.operation.Version

class SOPImpl(
    private val api: PGPainless = PGPainless.getInstance(),
    private val sopv: SOPV = SOPVImpl(api)
) : SOP {

    constructor(api: PGPainless) : this(api, SOPVImpl(api))

    override fun armor(): Armor = ArmorImpl(api)

    override fun certifyUserId(): CertifyUserId = CertifyUserIdImpl(api)

    override fun changeKeyPassword(): ChangeKeyPassword = ChangeKeyPasswordImpl(api)

    override fun dearmor(): Dearmor = DearmorImpl(api)

    override fun decrypt(): Decrypt = DecryptImpl(api)

    override fun detachedSign(): DetachedSign = DetachedSignImpl(api)

    override fun detachedVerify(): DetachedVerify = sopv.detachedVerify()!!

    override fun encrypt(): Encrypt = EncryptImpl(api)

    override fun extractCert(): ExtractCert = ExtractCertImpl(api)

    override fun generateKey(): GenerateKey = GenerateKeyImpl(api)

    override fun inlineDetach(): InlineDetach = InlineDetachImpl(api)

    override fun inlineSign(): InlineSign = InlineSignImpl(api)

    override fun inlineVerify(): InlineVerify = sopv.inlineVerify()!!

    override fun listProfiles(): ListProfiles = ListProfilesImpl(api)

    override fun mergeCerts(): MergeCerts = MergeCertsImpl(api)

    override fun revokeKey(): RevokeKey = RevokeKeyImpl(api)

    override fun updateKey(): UpdateKey = UpdateKeyImpl(api)

    override fun validateUserId(): ValidateUserId = sopv.validateUserId()!!

    override fun version(): Version = sopv.version()!!
}
