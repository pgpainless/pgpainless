// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;
import java.io.InputStream;

public interface ParserBackend {

    Certificate readCertificate(InputStream inputStream) throws IOException;

}
