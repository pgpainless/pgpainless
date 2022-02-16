// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.SubkeyLookup;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class InMemorySubkeyLookup implements SubkeyLookup {

    private static final Map<Long, Set<String>> subkeyMap = new HashMap<>();

    @Override
    public Set<String> getIdentifiersForSubkeyId(long subkeyId) {
        Set<String> identifiers = subkeyMap.get(subkeyId);
        if (identifiers == null) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(identifiers);
    }

    @Override
    public void storeIdentifierForSubkeyId(long subkeyId, String identifier) {
        Set<String> identifiers = subkeyMap.get(subkeyId);
        if (identifiers == null) {
            identifiers = new HashSet<>();
            subkeyMap.put(subkeyId, identifiers);
        }
        identifiers.add(identifier);
    }

    public void clear() {
        subkeyMap.clear();
    }
}
