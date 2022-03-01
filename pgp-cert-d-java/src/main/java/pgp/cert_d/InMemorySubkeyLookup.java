// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import pgp.certificate_store.SubkeyLookup;

public class InMemorySubkeyLookup implements SubkeyLookup {

    private static final Map<Long, Set<String>> subkeyMap = new HashMap<>();

    @Override
    public Set<String> getCertificateFingerprintsForSubkeyId(long subkeyId) {
        Set<String> identifiers = subkeyMap.get(subkeyId);
        if (identifiers == null) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(identifiers);
    }

    @Override
    public void storeCertificateSubkeyIds(String certificate, List<Long> subkeyIds) {
        for (long subkeyId : subkeyIds) {
            Set<String> certificates = subkeyMap.get(subkeyId);
            if (certificates == null) {
                certificates = new HashSet<>();
                subkeyMap.put(subkeyId, certificates);
            }
            certificates.add(certificate);
        }
    }

    public void clear() {
        subkeyMap.clear();
    }
}
