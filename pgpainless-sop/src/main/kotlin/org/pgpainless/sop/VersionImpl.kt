// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import java.util.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.pgpainless.PGPainless
import sop.SOP
import sop.operation.Version

/** Implementation of the `version` operation using PGPainless. */
class VersionImpl(private val api: PGPainless) : Version {

    companion object {
        const val SOP_VERSION = 15
        const val SOPV_VERSION = "1.2"
    }

    override fun getBackendVersion(): String = "PGPainless ${getVersion()}"

    override fun getExtendedVersion(): String {
        val bcVersion =
            String.format(
                Locale.US, "Bouncy Castle %.2f", BouncyCastleProvider().versionStr.toDouble())
        val specVersion = String.format("%02d", SOP_VERSION)
        return """${getName()} ${getVersion()}
https://codeberg.org/PGPainless/pgpainless/src/branch/main/pgpainless-sop

Implementation of the Stateless OpenPGP Protocol Version $specVersion
https://datatracker.ietf.org/doc/html/draft-dkg-openpgp-stateless-cli-$specVersion

Based on pgpainless-core ${getVersion()}
https://pgpainless.org
${formatSopJavaVersion()}
Using $bcVersion
https://www.bouncycastle.org/java.html"""
    }

    override fun getName(): String = "PGPainless-SOP"

    override fun getSopSpecImplementationRemarks(): String? = null

    override fun getSopSpecRevisionNumber(): Int = SOP_VERSION

    override fun getSopVVersion(): String = SOPV_VERSION

    override fun getVersion(): String {
        // See https://stackoverflow.com/a/50119235
        return try {
            val resourceIn: InputStream =
                SOP::class.java.getResourceAsStream("/pgpainless-sop.properties")
                    ?: throw IOException("File pgpainless-sop.properties not found.")

            val properties = Properties().apply { load(resourceIn) }
            properties.getProperty("pgpainless-sop-version")
        } catch (e: IOException) {
            "DEVELOPMENT"
        }
    }

    private fun formatSopJavaVersion(): String {
        return getSopJavaVersion()?.let {
            """
            
            sop-java $it
            
        """
                .trimIndent()
        }
            ?: ""
    }

    override fun isSopSpecImplementationIncomplete(): Boolean = false
}
