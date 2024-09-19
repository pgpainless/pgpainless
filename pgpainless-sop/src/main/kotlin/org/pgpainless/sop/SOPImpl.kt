// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

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

class SOPImpl(private val sopv: SOPV = SOPVImpl()) : SOP {

    override fun armor() = ArmorImpl()

    override fun certifyUserId() = null

    override fun changeKeyPassword() = ChangeKeyPasswordImpl()

    override fun dearmor() = DearmorImpl()

    override fun decrypt() = DecryptImpl()

    override fun detachedSign() = DetachedSignImpl()

    override fun detachedVerify() = sopv.detachedVerify()

    override fun encrypt() = EncryptImpl()

    override fun extractCert() = ExtractCertImpl()

    override fun generateKey() = GenerateKeyImpl()

    override fun inlineDetach() = InlineDetachImpl()

    override fun inlineSign() = InlineSignImpl()

    override fun inlineVerify() = sopv.inlineVerify()

    override fun listProfiles() = ListProfilesImpl()

    override fun mergeCerts() = null

    override fun revokeKey() = RevokeKeyImpl()

    override fun updateKey() = null

    override fun validateUserId() = null

    override fun version() = sopv.version()
}
