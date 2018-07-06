package ab3.test;

import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import ab3.AB3;
import ab3.CertTools;
import ab3.PasswordTools;
import ab3.PasswordTools.SaltedHash;
import ab3.impl.AuerEberlHarden.AB3Impl;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AB3Test {

    private AB3 ab3Impl = new AB3Impl();
    private CertTools crttools = ab3Impl.newCertToolsInstance();
    private PasswordTools pwdTools = ab3Impl.newPasswordToolsInstance();

    private static int pts;

    @Test
    public void testCampusAAUZerts() {
        crttools.loadServerCerts("support.dnsimple.com", 443);

        //Hole Zertifikat
        int testCert = crttools.getCertificateChain().get(0);

        Assert.assertEquals(4, crttools.getNumberCerts());

        Assert.assertEquals(
                "MIIGWzCCBUOgAwIBAgIRAKzmUxoonDDqhG6uN1EKv1QwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTYwNAYDVQQDEy1DT01PRE8gUlNBIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTgwNTI5MDAwMDAwWhcNMTkwNzI4MjM1OTU5WjBcMSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxHjAcBgNVBAsTFUVzc2VudGlhbFNTTCBXaWxkY2FyZDEXMBUGA1UEAwwOKi5kbnNpbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7k5jusiuBEYRhB7YGdKG8V1FClgw1CGBgUd8LrQGYxKb6L0panWxiiAffa4O6bRg/yXc/Mn1LwGhtjcnDn1Ftpx7ZfHy/iDQc8QDvlMx0uBvjY2BQ9QJnQKiWxOxJ8yzVZLGEb0lkwvGs48l5AqwaJ7kMdJ2C7iHdKIPLQp0UmEvu7A6xGdwRrb9bCkFNB5RHjhuOa8Sy9Zc3S9C6vgtaoVJokW6a5HZzBmmQbph0NoYvfK65V1znaj+IvsVB1GYFzUI4FcqV4Ecexi5sgdhEc+fddIomdjllwx54oaZtH5DOlOv4BzZoxBKilO0uG9TRLF2/dl673asH1q/NnezbAgMBAAGjggLhMIIC3TAfBgNVHSMEGDAWgBSQr2o6lFoL2JDqElZz30O0Oija5zAdBgNVHQ4EFgQUfHx+u06+1ZpQw8miuAkjxiUhiQQwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCME8GA1UdIARIMEYwOgYLKwYBBAGyMQECAgcwKzApBggrBgEFBQcCARYdaHR0cHM6Ly9zZWN1cmUuY29tb2RvLmNvbS9DUFMwCAYGZ4EMAQIBMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0NPTU9ET1JTQURvbWFpblZhbGlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcmwwgYUGCCsGAQUFBwEBBHkwdzBPBggrBgEFBQcwAoZDaHR0cDovL2NydC5jb21vZG9jYS5jb20vQ09NT0RPUlNBRG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZlckNBLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMCcGA1UdEQQgMB6CDiouZG5zaW1wbGUuY29tggxkbnNpbXBsZS5jb20wggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdQDuS723dc5guuFCaR+r4Z5mow9+X7By2IMAxHuJeqj9ywAAAWOrTyEcAAAEAwBGMEQCIF3Q263UASAaqh8jToWygps9uuhV7weFdTGcPjD2jMhkAiBYqJkhH3RGTONGAZqBjiH8WEa7fqPVfbkvC+gV28/0XAB3AHR+2oMxrTMQkSGcziVPQnDCv/1eQiAIxjc1eeYQe8xWAAABY6tPIXcAAAQDAEgwRgIhAOsnGQClk3q4zBcNb5RAHwn92kPjD7yjSdmPLvyOP9A7AiEAqTJLHazoI0QRWk1gfS/1Bj/Vg7Oa0PpIi9/hKL7Dz10wDQYJKoZIhvcNAQELBQADggEBADPFeeQpqkBZNh9RB29urmgvPZBRUr6oKz249P5DDDcuimYB6E2ZCBH+svMwzJN1esyx5ky5aLquphGDF3z4iFBIr6bhBObuxOAhenZn2+T07Cyphkxd6KRgKJZDHt5X6CLwji5VEgw4uohaGYF6IoDnU50u+85jIBdI7jacvjLXF2r9veNQOCLgbEzzE2ipMIlqAhDzRA5PACBLhiCjN4oksD+ZM3zZwVXLgdE4wR7y3viuZw/paqF4JS1CBbTwhEGNG2P8IGHvNlXyVfq7Q2GFq8tnVZZzZ3vDlIKV+IwYKtzWIQTLAhizf/hcebq9E0zYJ91G64LFOdDI65zgO8Q=",
                crttools.getCertRepresentation(testCert));

        Assert.assertEquals(
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5OY7rIrgRGEYQe2BnShvFdRQpYMNQhgYFHfC60BmMSm+i9KWp1sYogH32uDum0YP8l3PzJ9S8BobY3Jw59Rbace2Xx8v4g0HPEA75TMdLgb42NgUPUCZ0ColsTsSfMs1WSxhG9JZMLxrOPJeQKsGie5DHSdgu4h3SiDy0KdFJhL7uwOsRncEa2/WwpBTQeUR44bjmvEsvWXN0vQur4LWqFSaJFumuR2cwZpkG6YdDaGL3yuuVdc52o/iL7FQdRmBc1COBXKleBHHsYubIHYRHPn3XSKJnY5ZcMeeKGmbR+QzpTr+Ac2aMQSopTtLhvU0Sxdv3Zeu92rB9avzZ3s2wIDAQAB",
                crttools.getPublicKey(testCert));

        Assert.assertEquals(
                "M8V55CmqQFk2H1EHb26uaC89kFFSvqgrPbj0/kMMNy6KZgHoTZkIEf6y8zDMk3V6zLHmTLlouq6mEYMXfPiIUEivpuEE5u7E4CF6dmfb5PTsLKmGTF3opGAolkMe3lfoIvCOLlUSDDi6iFoZgXoigOdTnS77zmMgF0juNpy+MtcXav2941A4IuBsTPMTaKkwiWoCEPNEDk8AIEuGIKM3iiSwP5kzfNnBVcuB0TjBHvLe+K5nD+lqoXglLUIFtPCEQY0bY/wgYe82VfJV+rtDYYWry2dVlnNne8OUgpX4jBgq3NYhBMsCGLN/+Fx5ur0TTNgn3UbrgsU50MjrnOA7xA==",
                crttools.getSignature(testCert));

        Assert.assertEquals(false, crttools.isForCRLSign(testCert));
        Assert.assertEquals(true, crttools.isForDigitalSignature(testCert));
        Assert.assertEquals(false, crttools.isForKeyCertSign(testCert));
        Assert.assertEquals(true, crttools.isForKeyEncipherment(testCert));

        Assert.assertEquals("ace6531a289c30ea846eae37510abf54", crttools.getSerialNumber(testCert));

        Assert.assertEquals("2b2e6eead975366c148a6edba37c8c07", crttools.getIssuerSerialNumber(testCert));

        Assert.assertEquals("5079F5ACC97826B57EAB42E92B4C0813172A92D3", crttools.getSHA1Fingerprint(testCert));

        Assert.assertEquals("59C45EF06E7ECF7EDFAD8C963D39B854C4339F176AC49124B05EC67BFAA6948E", crttools.getSHA256Fingerprint(testCert));

        Assert.assertEquals("SHA256withRSA", crttools.getSignatureAlgorithmName(testCert));

        Assert.assertEquals("CN=*.dnsimple.com,OU=EssentialSSL Wildcard,OU=Domain Control Validated", crttools.getSubjectDistinguishedName(testCert).replaceAll(", ", ","));

        Assert.assertEquals("CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB", crttools.getIssuerDistinguishedName(testCert).replaceAll(", ", ","));

        Assert.assertEquals(true, crttools.verifyAllCerts());


        int rootCA = crttools.getCertificateChain().get(3);
        //Die RootCA hat sich selbst zertifiziert
        Assert.assertEquals(crttools.getSerialNumber(rootCA), crttools.getIssuerSerialNumber(rootCA));
        Assert.assertEquals(crttools.getSubjectDistinguishedName(rootCA), crttools.getIssuerDistinguishedName(rootCA));

        pts += 3;
    }

    @Test
    public void saltedHash() {
        createSaltedHash_NotNull();
        checkSaltedHash_PasswordValid();
        checkSaltedHash_LongPasswordValid();
        checkSaltedHash_PasswordInvalid();
        checkSaltedHash_HashInvalid();
        checkSaltedHash_SaltInvalid();

        pts += 2;
    }

    @Test
    public void PBKDF2() {
        createPBKDFNotNull();
        checkPBDF2PasswordValid();
        checkPBDF2InvalidDKLength();
        checkPBDF2IterDifferent();
        checkPBDF2DkLenOne();
        checkPBKDF2LongPasswordAndSalt();
        checkPBKDF2DkLenInvalidLength();
        checkPBKDFPwNull();
        checkPBKDFSaltNull();
        checkPBKDFIterationsInvalid();

        checkPBKDF2TestOne();
        checkPBKDF2TestTwo();
        checkPBKDF2TestThree();
        checkPBKDF2TestFour();
        checkPBKDF2TestFive();
        checkPBKDF2TestSix();

        pts += 2;
    }

    @Test
    public void BBS() {
        byte[] data = pwdTools.generateRandomBytes(10, 256);

        Assert.assertEquals(10, data.length);

        pts += 3;
    }

    @AfterClass
    public static void printPts() {
        System.out.println("Punkte: " + pts);
    }

    public void createSaltedHash_NotNull() {
        // Trivialer Test, welcher nur überprüft ob überhaupt ein Ergebnis
        // zurückgegeben wird.
        String pw = "geheim";

        SaltedHash saltedHash = pwdTools.createSaltedHash(pw);

        Assert.assertNotNull(saltedHash.getHash());
        Assert.assertNotNull(saltedHash.getSalt());
    }

    public void checkSaltedHash_PasswordValid() {
        // Überprüft ob erkannt wird wenn zwei Passwoerter gleich sind.
        String pw1 = "geheim";
        String pw2 = "geheim";

        SaltedHash saltedHash = pwdTools.createSaltedHash(pw1);

        Assert.assertTrue(pwdTools.checkSaltedHash(pw2, saltedHash));
    }

    public void checkSaltedHash_LongPasswordValid() {
        // Überprüft ob erkannt wird wenn zwei Passwoerter gleich sind.

        String pw1 = Stream.generate(() -> "Text").limit(1000).collect(Collectors.joining());

        SaltedHash saltedHash = pwdTools.createSaltedHash(pw1);

        Assert.assertTrue(pwdTools.checkSaltedHash(pw1, saltedHash));
    }

    public void checkSaltedHash_PasswordInvalid() {
        // Überprüft ob erkannt wird wenn zwei Passwoerter sich unterscheiden.
        String pw1 = "geheim";
        String pw2 = "falschespw";

        SaltedHash saltedHash = pwdTools.createSaltedHash(pw1);

        Assert.assertFalse(pwdTools.checkSaltedHash(pw2, saltedHash));
    }

    public void checkSaltedHash_HashInvalid() {
        // Überprüft ob erkannt wird, wenn der Hash verändert wird
        String pw1 = "geheim";
        String pw2 = "geheim";

        SaltedHash saltedHash = pwdTools.createSaltedHash(pw1);

        saltedHash.getHash()[0] = (byte) (saltedHash.getHash()[0] ^ (byte) 0xFF);

        Assert.assertFalse(pwdTools.checkSaltedHash(pw2, saltedHash));
    }

    public void checkSaltedHash_SaltInvalid() {
        // Überprüft ob erkannt wird, wenn der Hash verändert wird
        String pw1 = "geheim";
        String pw2 = "geheim";

        SaltedHash saltedHash = pwdTools.createSaltedHash(pw1);

        saltedHash.getSalt()[0] = (byte) (saltedHash.getSalt()[0] ^ (byte) 0xFF);

        Assert.assertFalse(pwdTools.checkSaltedHash(pw2, saltedHash));
    }

    public void createPBKDFNotNull() {
        // Trivialer Test, welcher nur überprüft ob überhaupt ein Ergebnis
        // zurückgegeben wird.
        String pw = "geheim";

        SaltedHash sh = pwdTools.createSaltedHash(pw);
        byte[] dk = pwdTools.PBKDF2(pw.getBytes(), sh.getSalt(), 4096, 512);

        Assert.assertNotNull(dk);
    }

    public void checkPBDF2PasswordValid() {
        // Überprüft ob erkannt wird wenn zwei Passwoerter gleich sind.

        String pw1 = "geheim";
        String pw2 = "geheim";

        SaltedHash sh1 = pwdTools.createSaltedHash(pw1);
        byte[] key1 = pwdTools.PBKDF2(pw1.getBytes(), sh1.getSalt(), 4096, 512);

        byte[] key2 = pwdTools.PBKDF2(pw2.getBytes(), sh1.getSalt(), 4096, 512);

        Assert.assertArrayEquals(key1, key2);
    }

    public void checkPBDF2InvalidDKLength() {
        // Überprüft ob erkannt wird, wenn sich die Laenge der übergeben
        // DK-Laengen unterscheiden.

        String pw1 = "geheim";
        String pw2 = "geheim";
        SaltedHash sh1 = pwdTools.createSaltedHash(pw1);
        byte[] key1 = pwdTools.PBKDF2(pw1.getBytes(), sh1.getSalt(), 4096, 512);

        byte[] key2 = pwdTools.PBKDF2(pw2.getBytes(), sh1.getSalt(), 4096, 128);

        Assert.assertNotNull(key1);
        Assert.assertNotNull(key2);
        Assert.assertFalse(Arrays.equals(key1, key2));
    }

    public void checkPBDF2IterDifferent() {
        // Überprüft ob sich die Ergebnisse unterscheiden, wenn
        // eine unterschiedliche Anzahl an Iterationen verwendet werden.

        String pw1 = "geheim";
        String pw2 = "geheim";
        SaltedHash sh1 = pwdTools.createSaltedHash(pw1);
        byte[] key1 = pwdTools.PBKDF2(pw1.getBytes(), sh1.getSalt(), 4096, 512);

        byte[] key2 = pwdTools.PBKDF2(pw2.getBytes(), sh1.getSalt(), 1024, 512);

        Assert.assertFalse(Arrays.equals(key1, key2));
    }

    public void checkPBDF2DkLenOne() {
        // Überprüft ob sich die dkLen anpasst wenn sie zu klein gewaehlt ist.

        String pw1 = "geheim";
        String pw2 = "geheim";
        SaltedHash sh1 = pwdTools.createSaltedHash(pw1);
        byte[] key1 = pwdTools.PBKDF2(pw1.getBytes(), sh1.getSalt(), 4096, 1);

        byte[] key2 = pwdTools.PBKDF2(pw2.getBytes(), sh1.getSalt(), 4096, 1);

        Assert.assertTrue(Arrays.equals(key1, key2));
    }

    public void checkPBKDF2LongPasswordAndSalt() {

        byte[] key1 = pwdTools.PBKDF2("passwordPASSWORDpassword".getBytes(),
                "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(), 4096, 25);
        byte[] key2 = pwdTools.PBKDF2("passwordPASSWORDpassword".getBytes(),
                "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(), 4096, 25);

        Assert.assertTrue(Arrays.equals(key1, key2));
    }

    public void checkPBKDF2DkLenInvalidLength() {
        // Überprüft ob null zurückgegebn wird wenn die Anzahl der Iterationen
        // < 1 ist.

        String pw1 = "geheim";
        SaltedHash sh1 = pwdTools.createSaltedHash(pw1);
        byte[] key1 = pwdTools.PBKDF2(pw1.getBytes(), sh1.getSalt(), 4096, -1);

        Assert.assertNull(key1);
    }

    public void checkPBKDFPwNull() {
        // Überprüft ob null zurückgegeben wird, wenn das übergebene
        // Password null ist.

        byte[] key1 = pwdTools.PBKDF2(null, "salt".getBytes(), 4096, 1);

        Assert.assertNull(key1);
    }

    public void checkPBKDFSaltNull() {
        // Überprüft ob null zurückgegeben wird, wenn der übergeben Salt
        // null ist.

        byte[] key1 = pwdTools.PBKDF2("geheim".getBytes(), null, 4096, 1);

        Assert.assertNull(key1);
    }

    public void checkPBKDFIterationsInvalid() {
        // Überprüft ob null zurückgegeben wird wenn die Anzahl der
        // Iterationen unzulaessig ist.

        byte[] key1 = pwdTools.PBKDF2("geheim".getBytes(), "salt".getBytes(), 0, 1);

        byte[] key2 = pwdTools.PBKDF2("geheim".getBytes(), "salt".getBytes(), -1, 1);

        Assert.assertNull(key1);
        Assert.assertNull(key2);
    }

    public void checkPBKDF2TestOne() {
        // Testfall 1 von https://tools.ietf.org/html/rfc6070;

        Assert.assertArrayEquals(pwdTools.PBKDF2("password".getBytes(), "salt".getBytes(), 1, 20),
                new byte[]{12, 96, -56, 15, -106, 31, 14, 113, -13, -87, -75, 36, -81, 96, 18, 6, 47, -32, 55, -90});
    }

    public void checkPBKDF2TestTwo() {
        // Testfall 2 von https://tools.ietf.org/html/rfc6070;

        Assert.assertArrayEquals(pwdTools.PBKDF2("password".getBytes(), "salt".getBytes(), 2, 20), new byte[]{-22, 108,
                1, 77, -57, 45, 111, -116, -51, 30, -39, 42, -50, 29, 65, -16, -40, -34, -119, 87});
    }

    public void checkPBKDF2TestThree() {
        // Testfall 3 von https://tools.ietf.org/html/rfc6070;

        Assert.assertArrayEquals(pwdTools.PBKDF2("password".getBytes(), "salt".getBytes(), 4096, 20), new byte[]{75, 0,
                121, 1, -73, 101, 72, -102, -66, -83, 73, -39, 38, -9, 33, -48, 101, -92, 41, -63});
    }

    public void checkPBKDF2TestFour() {
        // Testfall 4 von https://tools.ietf.org/html/rfc6070;

        Assert.assertArrayEquals(pwdTools.PBKDF2("password".getBytes(), "salt".getBytes(), 16777216, 20), new byte[]{
                -18, -2, 61, 97, -51, 77, -92, -28, -23, -108, 91, 61, 107, -94, 21, -116, 38, 52, -23, -124});
    }

    public void checkPBKDF2TestFive() {
        // Testfall 5 von https://tools.ietf.org/html/rfc6070;

        Assert.assertArrayEquals(
                pwdTools.PBKDF2("passwordPASSWORDpassword".getBytes(), "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(),
                        4096, 25),
                new byte[]{61, 46, -20, 79, -28, 28, -124, -101, -128, -56, -40, 54, 98, -64, -28, 74, -117, 41, 26,
                        -106, 76, -14, -16, 112, 56});
    }

    public void checkPBKDF2TestSix() {
        // Testfall 6 von https://tools.ietf.org/html/rfc6070;

        Assert.assertArrayEquals(pwdTools.PBKDF2("pass\0word".getBytes(), "sa\0lt".getBytes(), 4096, 16),
                new byte[]{86, -6, 106, -89, 85, 72, 9, -99, -52, 55, -41, -16, 52, 37, -32, -61});
    }

}
