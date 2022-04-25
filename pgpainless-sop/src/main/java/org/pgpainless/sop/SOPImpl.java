// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import com.sun.crypto.provider.SunJCE;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.pgpainless.implementation.BcImplementationFactory;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.implementation.JceImplementationFactory;
import sop.SOP;
import sop.operation.Armor;
import sop.operation.Dearmor;
import sop.operation.Decrypt;
import sop.operation.DetachInbandSignatureAndMessage;
import sop.operation.Encrypt;
import sop.operation.ExtractCert;
import sop.operation.GenerateKey;
import sop.operation.Sign;
import sop.operation.Verify;
import sop.operation.Version;
import sun.security.ec.SunEC;

import java.security.Provider;
import java.security.Security;

public class SOPImpl implements SOP {

    static {
        ImplementationFactory.setFactoryImplementation(new JceImplementationFactory());
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new SunJCE());
        Security.addProvider(new SunEC());
        new KeyFactorySpi();

        Provider bcProv = Security.getProvider("BC");
        Security.removeProvider("BC");
        Security.insertProviderAt(bcProv, 1);
    }

    @Override
    public Version version() {
        return new VersionImpl();
    }

    @Override
    public GenerateKey generateKey() {
        return new GenerateKeyImpl();
    }

    @Override
    public ExtractCert extractCert() {
        return new ExtractCertImpl();
    }

    @Override
    public Sign sign() {
        return new SignImpl();
    }

    @Override
    public Verify verify() {
        return new VerifyImpl();
    }

    @Override
    public Encrypt encrypt() {
        return new EncryptImpl();
    }

    @Override
    public Decrypt decrypt() {
        return new DecryptImpl();
    }

    @Override
    public Armor armor() {
        return new ArmorImpl();
    }

    @Override
    public Dearmor dearmor() {
        return new DearmorImpl();
    }

    @Override
    public DetachInbandSignatureAndMessage detachInbandSignatureAndMessage() {
        return new DetachInbandSignatureAndMessageImpl();
    }
}
