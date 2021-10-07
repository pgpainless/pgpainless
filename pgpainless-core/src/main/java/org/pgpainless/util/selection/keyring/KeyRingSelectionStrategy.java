// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring;

import java.util.Set;

import org.pgpainless.util.MultiMap;

public interface KeyRingSelectionStrategy<R, C, O> {

    boolean accept(O identifier, R keyRing);

    Set<R> selectKeyRingsFromCollection(O identifier, C keyRingCollection);

    MultiMap<O, R> selectKeyRingsFromCollections(MultiMap<O, C> keyRingCollections);
}
