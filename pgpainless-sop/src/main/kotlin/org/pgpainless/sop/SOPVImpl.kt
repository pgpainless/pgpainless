// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import org.pgpainless.util.ArmoredOutputStreamFactory
import sop.SOPV
import sop.operation.DetachedVerify
import sop.operation.InlineVerify
import sop.operation.Version

class SOPVImpl : SOPV {

    init {
        ArmoredOutputStreamFactory.setVersionInfo(null)
    }

    override fun detachedVerify(): DetachedVerify = DetachedVerifyImpl()

    override fun inlineVerify(): InlineVerify = InlineVerifyImpl()

    override fun version(): Version = VersionImpl()
}
