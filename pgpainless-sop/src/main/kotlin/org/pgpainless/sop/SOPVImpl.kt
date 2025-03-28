// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import org.pgpainless.PGPainless
import org.pgpainless.util.ArmoredOutputStreamFactory
import sop.SOPV
import sop.operation.DetachedVerify
import sop.operation.InlineVerify
import sop.operation.Version

class SOPVImpl(private val api: PGPainless) : SOPV {

    init {
        ArmoredOutputStreamFactory.setVersionInfo(null)
    }

    override fun detachedVerify(): DetachedVerify = DetachedVerifyImpl(api)

    override fun inlineVerify(): InlineVerify = InlineVerifyImpl(api)

    override fun version(): Version = VersionImpl(api)
}
