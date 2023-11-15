// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.util.List;

import sop.Profile;
import sop.exception.SOPGPException;
import sop.operation.ListProfiles;

import javax.annotation.Nonnull;

/**
 * Implementation of the <pre>list-profiles</pre> operation using PGPainless.
 *
 */
public class ListProfilesImpl implements ListProfiles {

    @Override
    @Nonnull
    public List<Profile> subcommand(@Nonnull String command) {

        switch (command) {
            case "generate-key":
                return GenerateKeyImpl.SUPPORTED_PROFILES;

            case "encrypt":
                return EncryptImpl.SUPPORTED_PROFILES;

            default:
                throw new SOPGPException.UnsupportedProfile(command);
        }
    }
}
