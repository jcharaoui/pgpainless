package org.pgpainless.wot.dijkstra.sq;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.ArmorUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLOutput;

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

    public PGPSecretKeyRing getFreshFooBankEmployeeKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankEmployeeKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankEmployeeCert.asc"));
    }

    public String getFooBankEmployeePassphrase() {
        return "iLoveWorking@FooBank";
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
    public void test() {
        URL url = getTestResourceURL("test_vectors/freshly_generated/foobankCaKey.asc");
    }

    private static InputStream getTestResourceInputStream(String resource) {
        InputStream inputStream = WotTestVectors.class.getClassLoader().getResourceAsStream(resource);
        if (inputStream == null) {
            throw new IllegalArgumentException(String.format("Unknown resource %s", resource));
        }
        return inputStream;
    }

    private static URL getTestResourceURL(String resource) {
        URL url = WotTestVectors.class.getClassLoader().getResource(resource);
        if (url == null) {
            throw new IllegalArgumentException(String.format("Unknown resource %s", resource));
        }

        return url;
    }

    @Test
    public void generate() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        generateCertificates();
    }

    private void generateCertificates() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        String fooBankEmployeePassphrase = "iLoveWorking@FooBank";
        PGPSecretKeyRing fooBankEmployeeKey = PGPainless.generateKeyRing()
                .modernKeyRing("Foo Bank Employee <employee@foobank.com>");
        PGPPublicKeyRing fooBankEmployeeCert = PGPainless.extractCertificate(fooBankEmployeeKey);
        System.out.println(ArmorUtils.toAsciiArmoredString(fooBankEmployeeKey));
        System.out.println(ArmorUtils.toAsciiArmoredString(fooBankEmployeeCert));

        String fooBankAdminPassphrase = "keepFooBankSecure";
        PGPSecretKeyRing fooBankAdminKey = PGPainless.generateKeyRing()
                .modernKeyRing("Foo Bank Admin <admin@foobank.com>", fooBankAdminPassphrase);
        PGPPublicKeyRing fooBankAdminCert = PGPainless.extractCertificate(fooBankAdminKey);
        System.out.println(ArmorUtils.toAsciiArmoredString(fooBankAdminKey));
        System.out.println(ArmorUtils.toAsciiArmoredString(fooBankAdminCert));

        PGPSecretKeyRing fooBankCustomerKey = PGPainless.generateKeyRing()
                .modernKeyRing("Customer <customer@example.com>");
        PGPPublicKeyRing fooBankCustomerCert = PGPainless.extractCertificate(fooBankCustomerKey);
        System.out.println(ArmorUtils.toAsciiArmoredString(fooBankCustomerKey));
        System.out.println(ArmorUtils.toAsciiArmoredString(fooBankCustomerCert));

        PGPSecretKeyRing fooBankAttackerKey = PGPainless.generateKeyRing()
                .modernKeyRing("Attacker <employee@barbank.com>");
        PGPPublicKeyRing fooBankAttackerCert = PGPainless.extractCertificate(fooBankAttackerKey);
        System.out.println(ArmorUtils.toAsciiArmoredString(fooBankAttackerKey));
        System.out.println(ArmorUtils.toAsciiArmoredString(fooBankAttackerCert));
    }
}
