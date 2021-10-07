// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor;

public class KeyRingEditorTest {

    @Test
    public void testConstructorThrowsNpeForNull() {
        assertThrows(NullPointerException.class,
                () -> new SecretKeyRingEditor(null));
    }
}
