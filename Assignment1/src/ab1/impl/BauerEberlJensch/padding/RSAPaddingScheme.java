package ab1.impl.BauerEberlJensch.padding;

public interface RSAPaddingScheme {

    /**
     * Get unique identifier for the padding scheme.
     */
    byte getIdentifier();

    /**
     * Get the maximum chunk length to encrypt.
     */
    int maximumPlainTextLength();

    /**
     * Get the maximum chunk length to encrypt.
     */
    int maximumCipherTextLength();

    /**
     * Encrypt given data.
     *
     * <p>
     *     {@code data.length} must be less than or equal to {@link #maxEncryptMessageLength()}.
     * </p>
     *
     * @param data Data to encrypt.
     * @return Encrypted data.
     */
    byte[] encrypt(byte[] data);

    /**
     * Decrypt
     *
     * @param data
     * @return
     */
    byte[] decrypt(byte[] data);
}
