// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.syntax_check;

import org.pgpainless.exception.MalformedOpenPgpMessageException;

public interface Syntax {

    Transition transition(State from, InputAlphabet inputAlphabet, StackAlphabet stackItem)
        throws MalformedOpenPgpMessageException;
}
