/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.signature;

import java.util.Comparator;

import org.bouncycastle.openpgp.PGPSignature;

public class SignatureCreationDateComparator implements Comparator<PGPSignature> {

    public static final Order DEFAULT_ORDER = Order.OLD_TO_NEW;

    public enum Order {
        OLD_TO_NEW,
        NEW_TO_OLD
    }

    private final Order order;

    public SignatureCreationDateComparator() {
        this(DEFAULT_ORDER);
    }

    public SignatureCreationDateComparator(Order order) {
        this.order = order;
    }

    @Override
    public int compare(PGPSignature one, PGPSignature two) {
        return order == Order.OLD_TO_NEW
                ? one.getCreationTime().compareTo(two.getCreationTime())
                : two.getCreationTime().compareTo(one.getCreationTime());
    }
}
