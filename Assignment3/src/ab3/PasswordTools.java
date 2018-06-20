package ab3;

/**
 * Interface für die Verwendung des RSA-Kryptosystems.
 * 
 * @author Raphael Wigoutschnigg
 */
public interface PasswordTools {

	/**
	 * Erzeugt einen Salted-Hash
	 * 
	 * @param password
	 *            Das Passwort
	 * @return SaltedHash-Objekt
	 */
    SaltedHash createSaltedHash(String password);

	/**
	 * Prüft, ob ein Passwort zum übergebenen Salted-Hash passt
	 * 
	 * @param password
	 *            Das Passwort
	 * @param hash
	 *            Der Salted-Hash
	 * @return ob das Passwort zum Salted-Hash passt
	 */
    boolean checkSaltedHash(String password, SaltedHash hash);

	/**
	 * Bestimmt einen Key mithilfe der PBKDF2-Funktion. Sind Parameter null, so
	 * sind diese nicht zu verwenden. Verwenden Sie als PRF (pseudo random
	 * function) eine Hashfunktion (vgl. Klasse MessageDigest)
	 * 
	 * @param password
	 *            Das Passwort
	 * @param salt
	 *            Der Salt
	 * @param iterations
	 *            Anzahl an Iterationen
	 * @param dkLen
	 *            Länge des erzeugten Schlüsseln (derived key length)
	 * @return den erzeugten Schlüssel
	 */
    byte[] PBKDF2(byte[] password, byte[] salt, int iterations, int dkLen);

	/**
	 * Generiert len-Bytes Zufallszahlen mit dem Blum-Blum-Shub-Generator. Bei
	 * den Primzahlen p und q des Generators (n=p*q), reicht es, wenn p-1 sowie
	 * q-1 einen großen Teiler hat, dh eine Safe Prime ist (bzw. p-1 eine
	 * Sophie-Germain-Primzahl ist).
	 * 
	 * @param len
	 *            Länge der zu erzeugenden Zufallszahlen
	 * @param secLen
	 *            Gibt die Bitlänge des Moduls n des BBS-Generators an
	 * @return len-Bytes mit Zufallszahlen
	 */
    byte[] generateRandomBytes(int len, int secLen);

	/**
	 * Hilfsklasse zur Speicherung eines Salted-Hashes
	 * 
	 * @author Raphael Wigoutschnigg
	 */
    class SaltedHash {

		public SaltedHash() {

		}

		public SaltedHash(byte[] hash, byte[] salt) {
			super();
			this.hash = hash;
			this.salt = salt;
		}

		private byte[] hash;
		private byte[] salt;

		public byte[] getHash() {
			return hash;
		}

		public void setHash(byte[] hash) {
			this.hash = hash;
		}

		public byte[] getSalt() {
			return salt;
		}

		public void setSalt(byte[] salt) {
			this.salt = salt;
		}

	}
}