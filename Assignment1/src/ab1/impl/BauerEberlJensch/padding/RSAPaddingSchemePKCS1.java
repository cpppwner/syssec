package ab1.impl.BauerEberlJensch.padding;

import ab1.RSA;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * PKCS1 v1.5 padding scheme.
 */
public class RSAPaddingSchemePKCS1 implements RSAPaddingScheme {

    private static final byte IDENTIFIER = 0x2A;

    private static final int MIN_PS_BYTES = 8;
    private static final int PS_OFFSET = 2;
    private static final int PADDING_BYTES = PS_OFFSET + MIN_PS_BYTES + 1;

    private final RSA.PublicKey publicKey;
    private final RSA.PrivateKey privateKey;
    private final SecureRandom random = new SecureRandom();

    public RSAPaddingSchemePKCS1(RSA.PublicKey publicKey, RSA.PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public byte getIdentifier() {
        return IDENTIFIER;
    }

    @Override
    public int maximumPlainTextLength() {
        // the computation below is equal to floor(publicKey.getN().bitLength() / 8.0) - padding bytes
        // but since it's just integer operations probably faster
        return modulLengthInBytes() - PADDING_BYTES;
    }

    @Override
    public int maximumCipherTextLength() {
        // the computation below is equal to ceil(publicKey.getN().bitLength() / 8.0)
        // but since it's just integer operations probably faster
        return (publicKey.getN().bitLength() + 7) / 8;
    }

    @Override
    public byte[] encrypt(byte[] data) {

        // internal sanity check - ensure the data length
        if (data.length > maximumPlainTextLength()) {
            throw new IllegalArgumentException("data.length is invalid");
        }

        // generate the random string for padding
        byte[] paddingString = generateRandomPaddingString(modulLengthInBytes() - 3 - data.length);

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

        // now do the real encryption
        BigInteger c = new BigInteger(1, message).modPow(publicKey.getE(), publicKey.getN());

        byte[] cipher = c.toByteArray();
        if (c.bitLength() % 8 == 0 && c.bitLength() / 8 != cipher.length) {
            // sign bit - leading 0
            cipher = Arrays.copyOfRange(cipher, 1, cipher.length);
        }

        if (cipher.length > maximumCipherTextLength()) {
            // just a sanity check
            throw new IllegalStateException("cipher too long (got=" + cipher.length + "; expected=" +maximumCipherTextLength()+ ")");
        }

        return cipher;
    }

    @Override
    public byte[] decrypt(byte[] data) {

        // internal sanity check - ensure the data length
        if (data.length > maximumCipherTextLength()) {
            throw new IllegalArgumentException("data.length is invalid");
        }

        // decrypt the chunk
        BigInteger decrypted = new BigInteger(1, data).modPow(privateKey.getD(), privateKey.getN());
        byte[] decryptedData = decrypted.toByteArray();
        if ((decrypted.bitLength() % 8) == 0 && decrypted.bitLength() / 8 != decryptedData.length) {
            // sign bit - leading 0
            decryptedData = Arrays.copyOfRange(decryptedData, 1, decryptedData.length);
        }

        // build up the resulting message
        byte[] result = new byte[modulLengthInBytes()];
        System.arraycopy(decryptedData, 0, result, result.length - decryptedData.length, decryptedData.length);

        // validate the padding
        if (result[0] != 0x00 && result[1] != 0x02) {
            // ok, something f*cked up the padding bytes
            // don't throw an exception, but rather return an empty byte array
            return new byte[0];
        }

        // ensure that at least the next 8 bytes are not zero
        for (int i = 0; i < MIN_PS_BYTES; i++) {
            if (result[i + PS_OFFSET] == 0) {
                // ok, data is invalid
                return new byte[0];
            }
        }

        // search for first zero byte after padding string
        int offset = PS_OFFSET + MIN_PS_BYTES;
        while (offset < result.length && result[offset] != 0) {
            offset += 1;
        }
        // offset is now at the trailing 0 byte of the padding
        // increment by one again and now the real message starts
        offset += 1;

        if (offset >= result.length) {
            return new byte[0];
        }

        return Arrays.copyOfRange(result, offset, result.length);
    }

    public static boolean isPKCS1PaddingScheme(byte[] cipher) {
        return cipher[0] == IDENTIFIER;
    }

    /**
     * Generate a random padding string, consisting of bytes which are not zero.
     * @param length  The length of the padding string in bytes.
     * @return A random padding string.
     */
    private byte[] generateRandomPaddingString(int length) {

        byte[] randomPaddingString = new byte[length];

        for (int i = 0; i < randomPaddingString.length; i++) {
            // NOTE: the padding string must not contain zeros
            // Therefore generate a random integer in the range [0, 255) and add 1
            // which results in an integer in range [1, 255]
            randomPaddingString[i] = (byte)(random.nextInt(255) + 1);
        }

        return randomPaddingString;

    }

    private int modulLengthInBytes() {
        return publicKey.getN().bitLength() /  8;
    }
}
