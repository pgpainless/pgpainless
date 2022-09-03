// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.logging.Logger;
import org.junit.platform.commons.logging.LoggerFactory;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Random;

/**
 * Evaluate performance of random number generators.
 */
public class RNGPerformanceTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(RNGPerformanceTest.class);
    private static final int bytesInMebiByte = 1024 * 1024;

    @Test
    public void evaluateRandomPerformance() {
        Random random = new Random();
        byte[] bytes = new byte[bytesInMebiByte];

        Instant start = Instant.now();
        random.nextBytes(bytes);
        Instant end = Instant.now();

        Duration duration = Duration.between(start, end);
        LOGGER.info(() -> String.format(
                "Random.nextBytes() took %s milliseconds to generate 1 MiB of data",
                duration.toMillis()));
    }

    @Test
    public void evaluateSecureRandomPerformance() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[bytesInMebiByte];

        Instant start = Instant.now();
        random.nextBytes(bytes);
        Instant end = Instant.now();

        Duration duration = Duration.between(start, end);
        LOGGER.info(() -> String.format(
                "SecureRandom.nextBytes() took %s milliseconds to generate 1 MiB of data",
                duration.toMillis()));
    }

    @Test
    public void evaluateSHA256BasedDigestRandomGeneratorPerformance() {
        SHA256Digest digest = new SHA256Digest();
        DigestRandomGenerator random = new DigestRandomGenerator(digest);
        byte[] bytes = new byte[bytesInMebiByte];

        Instant start = Instant.now();
        random.nextBytes(bytes);
        Instant end = Instant.now();

        Duration duration = Duration.between(start, end);
        LOGGER.info(() -> String.format(
                "SHA256-based DigestRandomGenerator.nextBytes() took %s milliseconds to generate 1 MiB of data",
                duration.toMillis()));
    }

    @Test
    public void evaluateSHA1BasedDigestRandomGeneratorPerformance() {
        SHA1Digest digest = new SHA1Digest();
        DigestRandomGenerator random = new DigestRandomGenerator(digest);
        byte[] bytes = new byte[bytesInMebiByte];

        Instant start = Instant.now();
        random.nextBytes(bytes);
        Instant end = Instant.now();

        Duration duration = Duration.between(start, end);
        LOGGER.info(() -> String.format(
                "SHA1-based DigestRandomGenerator.nextBytes() took %s milliseconds to generate 1 MiB of data",
                duration.toMillis()));
    }
}
