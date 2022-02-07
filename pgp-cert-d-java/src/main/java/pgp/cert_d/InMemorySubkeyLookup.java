// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.util.HashMap;
import java.util.Map;

public class InMemorySubkeyLookup implements SubkeyLookup {

    private static final Map<Long, String> subkeyMap = new HashMap<>();

    @Override
    public String getIdentifierForSubkeyId(long subkeyId) {
        return subkeyMap.get(subkeyId);
    }

    @Override
    public void storeIdentifierForSubkeyId(long subkeyId, String identifier) {
        subkeyMap.put(subkeyId, identifier);
    }

    public void clear() {
        subkeyMap.clear();
    }
}
