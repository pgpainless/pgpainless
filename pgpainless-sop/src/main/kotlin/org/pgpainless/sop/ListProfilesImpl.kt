// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import sop.Profile
import sop.exception.SOPGPException
import sop.operation.ListProfiles

/** Implementation of the `list-profiles` operation using PGPainless. */
class ListProfilesImpl : ListProfiles {

    override fun subcommand(command: String): List<Profile> =
        when (command) {
            "generate-key" -> GenerateKeyImpl.SUPPORTED_PROFILES
            "encrypt" -> EncryptImpl.SUPPORTED_PROFILES
            else -> throw SOPGPException.UnsupportedProfile(command)
        }
}
