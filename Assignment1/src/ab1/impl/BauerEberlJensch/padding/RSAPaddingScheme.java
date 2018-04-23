package ab1.impl.BauerEberlJensch.padding;

public interface RSAPaddingScheme {

    /**
     * Get unique identifier for the padding scheme.
     */
    byte getIdentifier();

    /**
     * Get the maximum chunk length to encode.
     */
    int maximumPlainTextLength();

    /**
     * Get the maximum chunk length to decode.
     */
    int maximumCipherTextLength();

    /**
     * Encode given message based on the padding scheme.
     *
     * <p>
     *     {@code data.length} must be less than or equal to {@link #maximumPlainTextLength()}.
     * </p>
     *
     * @param data Data to encode.
     * @return Padding scheme encoded message.
     */
    byte[] encode(byte[] data);

    /**
     * Decode given message based on the padding scheme.
     *
     * @param data
     * @return
     */
    byte[] decode(byte[] data);
}
