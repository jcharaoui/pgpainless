package org.pgpainless.wot.dijkstra.sq;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.Trustworthiness;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.util.Passphrase;

public class WotTestVectors {

    private static WotTestVectors INSTANCE = null;

    public static WotTestVectors getTestVectors() {
        if (INSTANCE == null) {
            INSTANCE = new WotTestVectors();
        }
        return INSTANCE;
    }

    public PGPSecretKeyRing getFreshFooBankCaKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankCaKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankCaCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankCaCert.asc"));
    }

    public String getFooBankCaPassphrase() {
        return "superS3cureP4ssphrase";
    }

    public SecretKeyRingProtector getFooBankCaProtector() {
        return SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(getFooBankCaPassphrase()));
    }

    public PGPSecretKeyRing getFreshFooBankEmployeeKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankEmployeeKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankEmployeeCert.asc"));
    }

    public String getFooBankEmployeePassphrase() {
        return "iLoveWorking@FooBank";
    }

    public SecretKeyRingProtector getFooBankEmployeeProtector() {
        return SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(getFooBankEmployeePassphrase()));
    }

    public PGPSecretKeyRing getFreshFooBankAdminKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankAdminKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankAdminCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankAdminCert.asc"));
    }

    public String getFooBankAdminPassphrase() {
        return "keepFooBankSecure";
    }

    public SecretKeyRingProtector getFooBankAdminProtector() {
        return SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(getFooBankAdminPassphrase()));
    }

    public PGPSecretKeyRing getFreshFooBankCustomerKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankCustomerKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankCustomerCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankCustomerCert.asc"));
    }

    public PGPSecretKeyRing getFreshBarBankEmployeeKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/barbankEmployeeKey.asc"));
    }

    public PGPPublicKeyRing getFreshBarBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/barbankEmployeeCert.asc"));
    }

    public PGPSecretKeyRing getFreshFakeFooBankEmployeeKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/fakeFoobankEmployeeKey.asc"));
    }

    public PGPPublicKeyRing getFreshFakeFooBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/fakeFoobankEmployeeCert.asc"));
    }

    @Test
    public void crossSign() throws IOException, PGPException {
        PGPSecretKeyRing freshFooBankCaKey = getFreshFooBankCaKey();
        PGPPublicKeyRing freshFooBankCaCert = getFreshFooBankCaCert();

        PGPSecretKeyRing freshFooBankEmployeeKey = getFreshFooBankEmployeeKey();
        PGPPublicKeyRing freshFooBankEmployeeCert = getFreshFooBankEmployeeCert();

        PGPSecretKeyRing freshFooBankAdminKey = getFreshFooBankAdminKey();
        PGPPublicKeyRing freshFooBankAdminCert = getFreshFooBankAdminCert();

        PGPSecretKeyRing freshFooBankCustomerKey = getFreshFooBankCustomerKey();
        PGPPublicKeyRing freshFooBankCustomerCert = getFreshFooBankCustomerCert();

        // CA signs Employee
        PGPPublicKeyRing caCertifiedFooBankEmployeeCert = PGPainless.certify()
                .userIdOnCertificate("Foo Bank Employee <employee@foobank.com>", freshFooBankEmployeeCert)
                .withKey(freshFooBankCaKey, getFooBankCaProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.addNotationData(false, "affiliation@foobank.com", "employee");
                    }
                })
                .getCertifiedCertificate();

        // Employee delegates trust to CA
        PGPPublicKeyRing employeeDelegatedCaCert = PGPainless.certify()
                .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(freshFooBankEmployeeKey, getFooBankEmployeeProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression("*@foobank.com$");
                        hashedSubpackets.setExportable(false);
                    }
                })
                .getCertifiedCertificate();

        // CA signs Admin
        PGPPublicKeyRing caCertifiedFooBankAdminCert = PGPainless.certify()
                .userIdOnCertificate("Foo Bank Admin <admin@foobank.com>", freshFooBankAdminCert)
                .withKey(freshFooBankCaKey, getFooBankCaProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.addNotationData(false, "affiliation@foobank.com", "administrator");
                    }
                })
                .getCertifiedCertificate();

        // Admin delegates trust to CA
        PGPPublicKeyRing adminDelegatedCaCert = PGPainless.certify()
                .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(freshFooBankAdminKey, getFooBankAdminProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression("*@foobank.com$");
                        hashedSubpackets.setExportable(false);
                    }
                })
                .getCertifiedCertificate();

        // Customer delegates trust to CA
        PGPPublicKeyRing customerDelegatedCaCert = PGPainless.certify()
                .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(freshFooBankCustomerKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression("*@foobank.com$");
                        hashedSubpackets.setExportable(false);
                    }
                })
                .getCertifiedCertificate();

        System.out.println(PGPainless.asciiArmor(caCertifiedFooBankEmployeeCert));
        System.out.println(PGPainless.asciiArmor(employeeDelegatedCaCert));
        System.out.println(PGPainless.asciiArmor(caCertifiedFooBankAdminCert));
        System.out.println(PGPainless.asciiArmor(freshFooBankCustomerCert));
    }

    private static InputStream getTestResourceInputStream(String resource) {
        InputStream inputStream = WotTestVectors.class.getClassLoader().getResourceAsStream(resource);
        if (inputStream == null) {
            throw new IllegalArgumentException(String.format("Unknown resource %s", resource));
        }
        return inputStream;
    }
}
