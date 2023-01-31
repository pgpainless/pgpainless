// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless;

import java.util.Collections;
import java.util.Map;

import org.pgpainless.sop.SOPImpl;
import sop.SOP;
import sop.testsuite.SOPInstanceFactory;

public class PGPainlessSopInstanceFactory extends SOPInstanceFactory {

    @Override
    public Map<String, SOP> provideSOPInstances() {
        return Collections.singletonMap("PGPainless-SOP", new SOPImpl());
    }
}
