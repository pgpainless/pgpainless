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
package sop;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import sop.util.Optional;

public class DecryptionResult {

    private final Optional<SessionKey> sessionKey;
    private final List<Verification> verifications;

    public DecryptionResult(SessionKey sessionKey, List<Verification> verifications) {
        this.sessionKey = Optional.ofNullable(sessionKey);
        this.verifications = Collections.unmodifiableList(verifications);
    }

    public Optional<SessionKey> getSessionKey() {
        return sessionKey;
    }

    public List<Verification> getVerifications() {
        return new ArrayList<>(verifications);
    }
}
