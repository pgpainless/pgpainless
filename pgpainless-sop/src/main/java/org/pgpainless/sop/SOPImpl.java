// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.SOP;
import sop.SOPV;
import sop.operation.Armor;
import sop.operation.ChangeKeyPassword;
import sop.operation.Dearmor;
import sop.operation.Decrypt;
import sop.operation.DetachedSign;
import sop.operation.DetachedVerify;
import sop.operation.InlineDetach;
import sop.operation.Encrypt;
import sop.operation.ExtractCert;
import sop.operation.GenerateKey;
import sop.operation.InlineSign;
import sop.operation.InlineVerify;
import sop.operation.ListProfiles;
import sop.operation.RevokeKey;
import sop.operation.Version;

import javax.annotation.Nonnull;

/**
 * Implementation of the <pre>sop</pre> API using PGPainless.
 * <pre> {@code
 * SOP sop = new SOPImpl();
 * }</pre>
 *
 * For a slimmed down interface that merely focuses on signature verification, see {@link SOPVImpl}.
 */
public class SOPImpl implements SOP {

    static {
        ArmoredOutputStreamFactory.setVersionInfo(null);
    }

    // Delegate for sig verification operations
    private final SOPV sopv = new SOPVImpl();

    @Override
    @Nonnull
    public Version version() {
        // Delegate to SOPV
        return sopv.version();
    }

    @Override
    @Nonnull
    public GenerateKey generateKey() {
        return new GenerateKeyImpl();
    }

    @Override
    @Nonnull
    public ExtractCert extractCert() {
        return new ExtractCertImpl();
    }

    @Override
    @Nonnull
    public DetachedSign sign() {
        return detachedSign();
    }

    @Override
    @Nonnull
    public DetachedSign detachedSign() {
        return new DetachedSignImpl();
    }

    @Override
    @Nonnull
    public InlineSign inlineSign() {
        return new InlineSignImpl();
    }

    @Override
    @Nonnull
    public DetachedVerify verify() {
        return detachedVerify();
    }

    @Override
    @Nonnull
    public DetachedVerify detachedVerify() {
        // Delegate to SOPV
        return sopv.detachedVerify();
    }

    @Override
    @Nonnull
    public InlineVerify inlineVerify() {
        // Delegate to SOPV
        return sopv.inlineVerify();
    }

    @Override
    @Nonnull
    public Encrypt encrypt() {
        return new EncryptImpl();
    }

    @Override
    @Nonnull
    public Decrypt decrypt() {
        return new DecryptImpl();
    }

    @Override
    @Nonnull
    public Armor armor() {
        return new ArmorImpl();
    }

    @Override
    @Nonnull
    public Dearmor dearmor() {
        return new DearmorImpl();
    }

    @Override
    @Nonnull
    public ListProfiles listProfiles() {
        return new ListProfilesImpl();
    }

    @Override
    @Nonnull
    public RevokeKey revokeKey() {
        return new RevokeKeyImpl();
    }

    @Override
    @Nonnull
    public ChangeKeyPassword changeKeyPassword() {
        return new ChangeKeyPasswordImpl();
    }

    @Override
    @Nonnull
    public InlineDetach inlineDetach() {
        return new InlineDetachImpl();
    }
}
