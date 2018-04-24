package ab1.impl.BauerEberlJensch.padding;

import java.util.Arrays;

/**
 * PKCS1 v1.5 padding scheme.
 */
public class RSAPaddingSchemePKCS1 implements RSAPaddingScheme {

    private static final byte PADDING_BYTE = (byte)0xff;

    private static final byte IDENTIFIER = 0x2A;

    private static final int MIN_PS_BYTES = 8;
    private static final int PS_OFFSET = 2;
    private static final int PADDING_BYTES = PS_OFFSET + MIN_PS_BYTES + 1;

    private final int modulusBitLength;

    public RSAPaddingSchemePKCS1(int modulusBitLength) {
        this.modulusBitLength = modulusBitLength;
    }

    @Override
    public byte getIdentifier() {
        return IDENTIFIER;
    }

    @Override
    public int maximumPlainTextLength() {
        // the computation below is equal to floor(publicKey.getN().bitLength() / 8.0) - padding bytes
        // but since it's just integer operations probably faster
        return modulusLengthInBytes() - PADDING_BYTES;
    }

    @Override
    public int maximumCipherTextLength() {
        // the computation below is equal to ceil(publicKey.getN().bitLength() / 8.0)
        // but since it's just integer operations probably faster
        return (modulusBitLength + 7) / 8;
    }

    @Override
    public byte[] encode(byte[] data) {

        // internal sanity check - ensure the data length
        if (data.length > maximumPlainTextLength()) {
            throw new IllegalArgumentException("data.length is invalid");
        }

        // generate the random string for padding
        byte[] paddingString = generatePaddingString(modulusLengthInBytes() - 3 - data.length);

        // build up the message for encryption
        byte[] message = new byte[data.length + 3 + paddingString.length];
        message[0] = 0x00; // would not be necessary, but just to show how the padding works
        message[1] = 0x02;
        // followed by the previously generated padding string
        System.arraycopy(paddingString, 0, message, PS_OFFSET, paddingString.length);
        // followed by another zero right after padding string
        message[paddingString.length + PS_OFFSET] = 0x00;
        // followed by the message to encrypt
        System.arraycopy(data, 0, message, paddingString.length + 3, data.length);

        return message;
    }

    @Override
    public byte[] decode(byte[] data) {

        // validate the padding
        if (data[0] != 0x00 && data[1] != 0x02) {
            // the data seems to be corrupt
            // don't throw an exception, but rather return an empty byte array
            return new byte[0];
        }

        int paddingCount = 0;
        int offset = PS_OFFSET;
        while (offset < data.length && data[offset] != 0) {
            if (data[offset] != PADDING_BYTE) {
                // data is incorrect
                return new byte[0];
            }

            paddingCount += 1;
            offset += 1;
        }

        if (paddingCount < MIN_PS_BYTES) {
            // too few padding bytes
            return new byte[0];
        }

        if (offset < data.length && data[offset] != 0) {
            // byte value is after padding string is not equal to expected one
            return new byte[0];
        }

        // offset is now at the trailing 0 byte of the padding
        // increment by one again and now the real message starts
        offset += 1;

        if (offset >= data.length) {
            // either the data is invalid, or message is intentionally empty
            return new byte[0];
        }

        return Arrays.copyOfRange(data, offset, data.length);
    }

    public static boolean isPKCS1PaddingScheme(byte[] cipher) {
        return cipher[0] == IDENTIFIER;
    }

    /**
     * Generate a padding string, consisting of bytes which are all set to {@link #PADDING_BYTE}.
     *
     * <p>
     *     Note the RFC described way would be to generate a random padding string of given length
     *     with random byte values which are all greater than zero.
     *     Due to the fact, that the unit tests want a deterministic behaviour this was changed
     *     to a defined content.
     * </p>
     *
     * @param length  The length of the padding string in bytes.
     * @return A random padding string.
     */
    private byte[] generatePaddingString(int length) {

        byte[] paddingString = new byte[length];

        for (int i = 0; i < paddingString.length; i++) {
            paddingString[i] = PADDING_BYTE;
        }

        return paddingString;
    }

    private int modulusLengthInBytes() {
        return modulusBitLength /  8;
    }
}
