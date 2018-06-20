package ab3.impl.Eberl;

import ab3.CertTools;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class CertToolsImpl implements CertTools {

    @Override
    public boolean loadServerCerts(String host, Integer port) {
        return false;
    }

    @Override
    public void setCerts(Set<X509Certificate> certs) {

    }

    @Override
    public int getNumberCerts() {
        return 0;
    }

    @Override
    public String getCertRepresentation(int cert) {
        return null;
    }

    @Override
    public String getPublicKey(int cert) {
        return null;
    }

    @Override
    public String getSignatureAlgorithmName(int cert) {
        return null;
    }

    @Override
    public String getSubjectDistinguishedName(int cert) {
        return null;
    }

    @Override
    public String getIssuerDistinguishedName(int cert) {
        return null;
    }

    @Override
    public Date getValidFrom(int cert) {
        return null;
    }

    @Override
    public Date getValidUntil(int cert) {
        return null;
    }

    @Override
    public String getSerialNumber(int cert) {
        return null;
    }

    @Override
    public String getIssuerSerialNumber(int cert) {
        return null;
    }

    @Override
    public String getSignature(int cert) {
        return null;
    }

    @Override
    public String getSHA1Fingerprint(int cert) {
        return null;
    }

    @Override
    public String getSHA256Fingerprint(int cert) {
        return null;
    }

    @Override
    public boolean isForDigitalSignature(int cert) {
        return false;
    }

    @Override
    public boolean isForKeyEncipherment(int cert) {
        return false;
    }

    @Override
    public boolean isForKeyCertSign(int cert) {
        return false;
    }

    @Override
    public boolean isForCRLSign(int cert) {
        return false;
    }

    @Override
    public boolean verifyAllCerts() {
        return false;
    }

    @Override
    public int getIssuerCertNumber(int cert) {
        return 0;
    }

    @Override
    public List<Integer> getCertificateChain() {
        return null;
    }
}
