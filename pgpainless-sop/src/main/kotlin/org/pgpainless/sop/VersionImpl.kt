// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.util.*
import sop.operation.Version

/** Implementation of the `version` operation using PGPainless. */
class VersionImpl : Version {

    companion object {
        const val SOP_VERSION = 10
        const val SOPV_VERSION = "1.0"
    }

    override fun getBackendVersion(): String = "PGPainless ${getVersion()}"

    override fun getExtendedVersion(): String {
        // val bcVersion =
        //    String.format(Locale.US, "Bouncy Castle %.2f", BouncyCastleProvider().version)
        val bcVersion = "Bouncy Castle 1.79 + V6-Patches"
        val specVersion = String.format("%02d", SOP_VERSION)
        return """${getName()} ${getVersion()}
https://codeberg.org/PGPainless/pgpainless/src/branch/master/pgpainless-sop

Implementation of the Stateless OpenPGP Protocol Version $specVersion
https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-$specVersion

Based on pgpainless-core ${getVersion()}
https://pgpainless.org

Using $bcVersion
https://www.bouncycastle.org/java.html"""
    }

    override fun getName(): String = "PGPainless-SOP"

    override fun getSopSpecImplementationRemarks(): String? = null

    override fun getSopSpecRevisionNumber(): Int = SOP_VERSION

    override fun getSopVVersion(): String = SOPV_VERSION

    override fun getVersion(): String {
        return "1.7.0-V6_PREVIEW"
        // See https://stackoverflow.com/a/50119235
        /*
        return try {
            val resourceIn: InputStream =
                javaClass.getResourceAsStream("/version.properties")
                    ?: throw IOException("File version.properties not found.")

            val properties = Properties().apply { load(resourceIn) }
            properties.getProperty("version")
        } catch (e: IOException) {
            "DEVELOPMENT"
        }
         */
    }

    override fun isSopSpecImplementationIncomplete(): Boolean = false
}
