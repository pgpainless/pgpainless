/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.pgpainless.key.selection.key;

import java.util.Set;

import org.pgpainless.pgpainless.util.MultiMap;


/**
 * Interface that describes a selection strategy for OpenPGP keys.
 * @param <K> Type of the Key
 * @param <R> Type of the KeyRing
 * @param <O> Type that describes the owner of this key
 */
public interface KeySelectionStrategy<K, R, O> {

    boolean accept(O identifier, K key);

    Set<K> selectKeysFromKeyRing(O identifier, R ring);

    MultiMap<O, K> selectKeysFromKeyRings(MultiMap<O, R> rings);

}
