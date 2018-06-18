package ab3;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Schnittstelle zum Lesen von X509-Zertifikaten
 * 
 * @author Raphael Wigoutschnigg, Peter Schartner
 * 
 */
public interface CertTools {
	/**
	 * Läd SSL-Zertifikate des angegebenen Servers (inkl. Port) via HTTPS.
	 * Überschreibt bisher gespeicherte Zertifikate. Wird kein Port übergeben, so ist der Standard-HTTPS-Port zu verwenden.
	 * 
	 * @param host
	 *            Hostname
	 * @param port
	 *            Port
	 */
	public boolean loadServerCerts(String host, Integer port);

	/**
	 * Übergibt eine Menge an Zertifikaten. Überschreibt bisher gespeicherte
	 * Zertifikate.
	 * 
	 * @param certs
	 *            Menge an Zertifikaten
	 * @return Liefert true, wenn die Zertifikate geladen wurden. Andernfalls false.
	 */
	public void setCerts(Set<X509Certificate> certs);

	/**
	 * Liefert die Anzahl der gespeicherten Zertifikate. Diese Methode wird
	 * benötigt, um später auf das jeweilige Zertifikat zugreifen zu können.
	 * 
	 * @return Anzahl der gespeicherten Zertifikate
	 */
	public int getNumberCerts();

	/**
	 * Liefert die Base64-Darstellung des jeweiligen Zertifikats ohne Zeilenumbrüche.
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return Base64-Darstellung des Zertifikats oder null im Fehlerfall
	 */
	public String getCertRepresentation(int cert);

	/**
	 * Liefert die Base64-Darstellung des jeweiligen öffentlichen Schlüssels ohne Zeilenumbrüche.
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return Base64-Darstellung des öffentlichen Schlüssels
	 */
	public String getPublicKey(int cert);

	/**
	 * Liefert den Namen des verwendeten Signatur-Verfahrens
	 * 
	 * @param cert
	 *            cert die Nummer des Zertifikats mit 0 <= cert <
	 *            getNumberCerts()
	 * @return Name des verwendeten Signatur-Verfahrens
	 */
	public String getSignatureAlgorithmName(int cert);

	/**
	 * Liefert den Distinguished Name des Zertifikatinhabers
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return Distinguished Name des Zertifikatinhabers
	 */
	public String getSubjectDistinguishedName(int cert);

	/**
	 * Liefert den Distinguished Name des Ausstellers
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return Distinguished Name des Ausstellers
	 */
	public String getIssuerDistinguishedName(int cert);

	/**
	 * Liefert den Beginn der Gültigkeit des Zertifikats
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return Beginn der Gültigkeit des Zertifikats
	 */
	public Date getValidFrom(int cert);

	/**
	 * Liefert das Ende der Gültigkeit des Zertifikats
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return Ende der Gültigkeit des Zertifikats
	 */
	public Date getValidUntil(int cert);

	/**
	 * Liefert die HEX-Darstellung der Serienummer des Zertifikats
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return HEX-Darstellung der Seriennummer
	 */
	public String getSerialNumber(int cert);

	/**
	 * Liefert die HEX-Darstellung der Seriennummer des Ausstellers
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return HEX-Darstellung der Seriennummer des Ausstellers
	 */
	public String getIssuerSerialNumber(int cert);

	/**
	 * Liefert die Base64-Darstellung der enthaltenen Signatur des Zertifikats ohne Zeilenumbrüche
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return Base64-Darstellung der enthaltenen Signatur
	 */
	public String getSignature(int cert);

	/**
	 * Liefert die HEX-Darstellung des SHA1-Fingerprints
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return HEX-Darstellung des SHA1-Fingerprints oder null im Fehlerfall
	 */
	public String getSHA1Fingerprint(int cert);

	/**
	 * Liefert die HEX-Darstellung des SHA256-Fingerprints
	 * 
	 * @param cert
	 *            die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return HEX-Darstellung des SHA356-Fingerprints oder null im Fehlerfall
	 */
	public String getSHA256Fingerprint(int cert);

	/**
	 * Liefert, ob das Schlüsselpaar für digtiale Signaturen verwendet werden darf
	 * @param cert die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return true, wenn das Schlüsselpaar für digitale Signaturen verwendet werden darf
	 */
	public boolean isForDigitalSignature(int cert);

	/**
	 * Liefert, ob das Schlüsselpaar für die Verschlüsselung von Sitzungsschlüssel verwendet werden darf
	 * @param cert die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return true, wenn das Schlüsselpaar für die Verschlüsselung von Sitzungsschlüsseln verwendet werden darf
	 */
	public boolean isForKeyEncipherment(int cert);

	/**
	 * Liefert, ob das Schlüsselpaar für die Signatur von Public-Key-Zertifikaten verwendet werden darf
	 * @param cert die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return true, wenn das Schlüsselpaar für die Signatur von Public-Key-Zertifikaten verwendet werden darf
	 */
	public boolean isForKeyCertSign(int cert);

	/**
	 * Liefert, ob das Schlüsselpaar für die Signatur von CRLs verwendet werden darf
	 * @param cert die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return true, wenn das Schlüsselpaar für die Signatur von CRLs verwendet werden darf
	 */
	public boolean isForCRLSign(int cert);

	/**
	 * Prüft, ob die Zertifikate alle korrekt signiert sind. Root-Zertifikaten (Selbstsignatur) wird vertraut
	 * @return True, wenn die Signaturen aller Zertifikate korrekt überprüft wurden
	 */
	public boolean verifyAllCerts();

	/**
	 * Liefert für das gegebene Zertifikat die Nummer des Zertifikats des Ausstelles.
	 * @param cert die Nummer des Zertifikats mit 0 <= cert < getNumberCerts()
	 * @return Nummer des Zertifikats des Ausstellers. Falls nicht vorhanden -1
	 */
	public int getIsserCertNumber(int cert);

	/**
	 * Lierfert die Zertifikatskette (intern verwendete Inidzes). Der letzte Index entspricht dem Root-CA.
	 * @return Nummern der Zertifikate anhand der Zertifikatskette
	 */
	public List<Integer> getCertificateChain();
}
