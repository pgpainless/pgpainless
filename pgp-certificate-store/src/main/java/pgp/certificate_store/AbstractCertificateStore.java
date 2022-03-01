// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public abstract class AbstractCertificateStore implements CertificateStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractCertificateStore.class);

    public Set<Certificate> getCertificatesBySubkeyId(long subkeyId)
            throws IOException {
        Set<String> identifiers = getCertificateFingerprintsForSubkeyId(subkeyId);
        if (identifiers.isEmpty()) {
            return Collections.emptySet();
        }

        Set<Certificate> certificates = new HashSet<>();
        for (String identifier : identifiers) {
            try {
                certificates.add(getCertificate(identifier));
            } catch (BadNameException | BadDataException e) {
                LOGGER.warn("Could not read certificate.", e);
            }
        }

        return certificates;
    }
}
