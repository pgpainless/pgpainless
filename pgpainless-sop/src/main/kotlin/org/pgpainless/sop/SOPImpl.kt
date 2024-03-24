// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import sop.SOP
import sop.SOPV
import sop.operation.Armor
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
import sop.operation.RevokeKey
import sop.operation.Version

class SOPImpl(private val sopv: SOPV = SOPVImpl()) : SOP {

    override fun armor(): Armor = ArmorImpl()

    override fun changeKeyPassword(): ChangeKeyPassword = ChangeKeyPasswordImpl()

    override fun dearmor(): Dearmor = DearmorImpl()

    override fun decrypt(): Decrypt = DecryptImpl()

    override fun detachedSign(): DetachedSign = DetachedSignImpl()

    override fun detachedVerify(): DetachedVerify = sopv.detachedVerify()

    override fun encrypt(): Encrypt = EncryptImpl()

    override fun extractCert(): ExtractCert = ExtractCertImpl()

    override fun generateKey(): GenerateKey = GenerateKeyImpl()

    override fun inlineDetach(): InlineDetach = InlineDetachImpl()

    override fun inlineSign(): InlineSign = InlineSignImpl()

    override fun inlineVerify(): InlineVerify = sopv.inlineVerify()

    override fun listProfiles(): ListProfiles = ListProfilesImpl()

    override fun revokeKey(): RevokeKey = RevokeKeyImpl()

    override fun version(): Version = sopv.version()
}
