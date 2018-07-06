package ab3.impl.AuerEberlHarden;

import ab3.CertTools;

import javax.net.ssl.*;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Default implementation for cert tools
 *
 * @author Thomas Auer
 * @author Stefan Eberl
 * @author Igor Harden
 */
public class CertToolsImpl implements CertTools {

    /**
     * Default port for loading server certificates, if {@code null} is given.
     */
    private static final int DEFAULT_HTTPS_PORT = 443;

    /**
     * Hex values
     */
    private static final char[] HEX_VALUES = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    private List<X509Certificate> certificates;

    @Override
    public boolean loadServerCerts(String host, Integer port) {

        if (port == null) {
            // use default port if none was given
            port = DEFAULT_HTTPS_PORT;
        }

        try {
            Certificate[] serverCertificates = getServerCertificates(host, port);
            certificates = new ArrayList<>(serverCertificates.length);
            Arrays.stream(serverCertificates).forEach(c -> certificates.add((X509Certificate)c));
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Initiate connection with server and get peer's certificates.
     *
     * @param host Host to connect to.
     * @param port Port to connect to.
     * @return An array containing the peer's certificates.
     * @throws Exception If something goes wrong.
     */
    private static Certificate[] getServerCertificates(String host, int port) throws Exception {

        // get SSL context & initialize SSLContext
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, new TrustManager[]{new BlindX509TrustManager()}, null);
        // get SSLSocketFactory & create socket
        SSLSocketFactory factory = sc.getSocketFactory();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
            // start SSL/TLS handshake with remote side.
            socket.startHandshake();
            // get SSL/TLS session from socket & return the peer certificates from sesson
            SSLSession session = socket.getSession();
            return session.getPeerCertificates();
        }
    }

    @Override
    public void setCerts(Set<X509Certificate> certs) {

        certificates = new ArrayList<>(certs);
    }

    @Override
    public int getNumberCerts() {

        return certificates.size();
    }

    @Override
    public String getCertRepresentation(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        try {
            return base64Encode(certificates.get(cert).getEncoded());
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public String getPublicKey(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return base64Encode(certificates.get(cert).getPublicKey().getEncoded());
    }

    @Override
    public String getSignatureAlgorithmName(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return certificates.get(cert).getSigAlgName();
    }

    @Override
    public String getSubjectDistinguishedName(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return certificates.get(cert).getSubjectX500Principal().getName();
    }

    @Override
    public String getIssuerDistinguishedName(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return certificates.get(cert).getIssuerX500Principal().getName();
    }

    @Override
    public Date getValidFrom(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return certificates.get(cert).getNotBefore();
    }

    @Override
    public Date getValidUntil(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return certificates.get(cert).getNotAfter();
    }

    @Override
    public String getSerialNumber(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return certificates.get(cert).getSerialNumber().toString(16);
    }

    @Override
    public String getIssuerSerialNumber(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return getSerialNumber(getIsserCertNumber(cert));
    }

    @Override
    public String getSignature(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        return base64Encode(certificates.get(cert).getSignature());
    }

    @Override
    public String getSHA1Fingerprint(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        try {
            return toHexString(MessageDigest.getInstance("SHA1").digest(certificates.get(cert).getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public String getSHA256Fingerprint(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return null;
        }

        try {
            return toHexString(MessageDigest.getInstance("SHA-256").digest(certificates.get(cert).getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public boolean isForDigitalSignature(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return false;
        }

        return certificates.get(cert).getKeyUsage()[0];
    }

    @Override
    public boolean isForKeyEncipherment(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return false;
        }

        return certificates.get(cert).getKeyUsage()[2];
    }

    @Override
    public boolean isForKeyCertSign(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return false;
        }

        return certificates.get(cert).getKeyUsage()[5];
    }

    @Override
    public boolean isForCRLSign(int cert) {

        if (cert < 0 || cert >= getNumberCerts()) {
            // sanity check
            return false;
        }

        return certificates.get(cert).getKeyUsage()[6];
    }

    @Override
    public boolean verifyAllCerts() {

        // loop over all certificates
        // if verification of one fails, then this whole method fails
        for (int certificateIndex = 0; certificateIndex < getNumberCerts(); certificateIndex++) {

            int issuerCertificateIndex = getIsserCertNumber(certificateIndex);
            if (issuerCertificateIndex < 0 || issuerCertificateIndex >= getNumberCerts()) {
                // did not find an appropriate issuer
                return false;
            }

            if (!verify(certificates.get(certificateIndex), certificates.get(issuerCertificateIndex))) {
                return false;
            }
        }

        return true;
    }

    /**
     * Verify certificate with issuer certificate.
     *
     * @param certificate The certificate to verify.
     * @param issuerCertificate The issuer certificate.
     * @return {@code true} if verification was successful, {@code false otherwise.}
     */
    private boolean verify(X509Certificate certificate, X509Certificate issuerCertificate) {

        try {
            certificate.verify(issuerCertificate.getPublicKey());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public int getIsserCertNumber(int cert) {

        String issuerDN = getIssuerDistinguishedName(cert);
        if (issuerDN == null) {
            return cert; // wrong index
        }

        for (int i = 0; i < getNumberCerts(); i++) {
            if (getSubjectDistinguishedName(i).equals(issuerDN)) {
                return i;
            }
        }

        return -1; // did not find appropriate issuer
    }

    @Override
    public List<Integer> getCertificateChain() {

        // get first certificate
        Set<String> issuerDNs = certificates.stream().map(c -> c.getIssuerX500Principal().getName()).collect(Collectors.toSet());

        int certificateIndex = 0;
        for (int i = 0; i < getNumberCerts(); i++, certificateIndex++) {
            if (!issuerDNs.contains(getSubjectDistinguishedName(i))) {
                break;
            }
        }

        if (certificateIndex >= getNumberCerts()) {
            // did not find any appropriate first index
            return Collections.emptyList();
        }

        List<Integer> certificateChain = new ArrayList<>(certificates.size());
        certificateChain.add(certificateIndex);

        while(getIsserCertNumber(certificateIndex) != certificateIndex) {
            certificateIndex = getIsserCertNumber(certificateIndex);
            certificateChain.add(certificateIndex);
        }

        return certificateChain;
    }

    /**
     * Encode given {@code data} to Base64 string representation.
     *
     * @param data The data to encode.
     * @return String encoded data.
     */
    private static String base64Encode(byte[] data) {

        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(data);
    }

    /**
     * Convert given byte array to hex string representation.
     *
     * @param data The data to convert to hex string.
     * @return Hex string representation of {@code data}.
     */
    private static String toHexString(byte[] data) {

        StringBuilder resultBuilder = new StringBuilder(data.length * 2);
        for(int b : data) {
            resultBuilder.append(HEX_VALUES[(b & 0XF0) >>> 4]).append(HEX_VALUES[b & 0x0F]);
        }

        return resultBuilder.toString();
    }

    /**
     * Special X509Trust manager accepting all certificates.
     *
     * <p>
     * This class is copied from https://github.com/Dynatrace/openkit-java/blob/master/src/main/java/com/dynatrace/openkit/protocol/ssl/SSLBlindTrustManager.java
     * and remains under Copyright of Dynatrace ;)
     * </p>
     */
    private static class BlindX509TrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {
            // intentionally left empty to trust everything
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {
            // intentionally left empty to trust everything
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}


