package ab1.impl.BauerEberlJensch.signature;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Helper class for signature encoding/decoding.
 *
 * <p>
 *     The implementation for encoding/decoding is EMSA-PKCS1 v1.5 (based on https://tools.ietf.org/html/rfc3447).
 * </p>
 */
public class PKCS1 {

    private static final int MIN_PADDING_STRING_LENGTH = 8;
    private static final int NUM_EXTRA_PADDING_BYTES = 3;

    private static final int PADDING_STRING_OFFSET = 2;

    private static final byte PADDING_STRING_BYTE = (byte)0xff;

    /**
     * Some prefix as specified in the RFC 3447
     */
    private static final byte[] SHA256_DIGEST_INFO_PREFIX = new byte[] {
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };

    /**
     * Default constructor is empty, since this is a static utility class.
     */
    private PKCS1() {}

    /**
     * Encode the given message for signing using EMSA-PKCS1 v1.5.
     *
     * @param message The plain text message to encode.
     * @param encodedMessageLength Intended length in bytes of the encoded message.
     * @return Encoded message or {@code null} if something fails (e.g. {@code encodedMessageLength} too small).
     */
    public static byte[] encode(byte[] message, int encodedMessageLength) {

        // 1. Apply the hash function to the message M to produce a hash value H
        byte[] hash = SHA256(message);

        // 2. Encode the algorithm ID for the hash function and the hash value
        // into an ASN.1 value of type DigestInfo
        byte[] digestInfo = generateDigestInfo(hash);

        //  3. If emLen < tLen + 11, output "intended encoded message length too short" and stop.
        if (encodedMessageLength < digestInfo.length + MIN_PADDING_STRING_LENGTH + NUM_EXTRA_PADDING_BYTES) {
            // don't stop here, but rather return null
            return null;
        }

        // 4. Generate an octet string PS consisting of emLen - tLen - 3 octets
        // with hexadecimal value 0xff.  The length of PS will be at least 8
        // octets.
        byte[] paddingString = generatePaddingString(encodedMessageLength - digestInfo.length - NUM_EXTRA_PADDING_BYTES);

        // 5. Concatenate PS, the DER encoding T, and other padding to form the encoded message
        byte[] encodedMessage = new byte[encodedMessageLength];
        encodedMessage[0] = 0x00; // not necessary, just showing how the padding works
        encodedMessage[1] = 0x01;
        System.arraycopy(paddingString, 0, encodedMessage, PADDING_STRING_OFFSET, paddingString.length);
        encodedMessage[PADDING_STRING_OFFSET + paddingString.length] = 0x00;
        System.arraycopy(digestInfo, 0, encodedMessage, PADDING_STRING_OFFSET  + paddingString.length + 1, digestInfo.length);

        // 6. output encoded message
        return encodedMessage;
    }


    /**
     * Verify that message is part of the encoded message.
     *
     * <p>
     *     This is an appropriate signature verification algorithm,
     *     assuming that the encoded message is already decrypted.
     * </p>
     *
     * @param encodedMessage The encoded, but already decrypted message.
     * @param message The plain message to verify.
     * @return {@code true} if signature is valid, {@code false} otherwise.
     */
    public static boolean verify(byte[] encodedMessage, byte[] message) {

        // generate digest info for the raw message
        byte[] hash = SHA256(message);
        byte[] digestInfo = generateDigestInfo(hash);

        // verify that encoded message has at least the expected length
        if (encodedMessage.length < digestInfo.length + 11)

        // check the first two bytes
        if (encodedMessage[0] != 0x00 || encodedMessage[1] != 0x01) {
            return false;
        }

        // ensure that there are at least 8 padding bytes with value 0xFF
        int numPaddingBytes = 0;
        for (int i = PADDING_STRING_OFFSET; i < encodedMessage.length; i++) {
            if (encodedMessage[i] != PADDING_STRING_BYTE) {
                break;
            }
            numPaddingBytes += 1;
        }
        if (numPaddingBytes < MIN_PADDING_STRING_LENGTH) {
            // number of padding bytes is invalid
            return false;
        }

        // now check the value
        int offset = PADDING_STRING_OFFSET + numPaddingBytes;
        if (offset >= encodedMessage.length || encodedMessage[offset] != 0x00) {
            // byte after padding string is invalid
            return false;
        }

        // extract the remaining parts and ensure it's equal to the previously generated digestInfo
        offset += 1;
        if (encodedMessage.length - offset != digestInfo.length) {
            return false;
        }
        return Arrays.equals(Arrays.copyOfRange(encodedMessage, offset, encodedMessage.length), digestInfo);
    }

    /**
     * Generate digest information.
     *
     * <p>
     *     The digest information contains information about the hash algorithm,
     *     concatenated with the hash value itself.
     * </p>
     *
     * @param hash The message digest.
     * @return Digest information.
     */
    private static byte[] generateDigestInfo(byte[] hash) {

        byte[] digestInfo = new byte[SHA256_DIGEST_INFO_PREFIX.length + hash.length];
        System.arraycopy(SHA256_DIGEST_INFO_PREFIX, 0, digestInfo, 0, SHA256_DIGEST_INFO_PREFIX.length);
        System.arraycopy(hash, 0, digestInfo, SHA256_DIGEST_INFO_PREFIX.length, hash.length);
        return digestInfo;
    }


    /**
     * Utility method to generate a padding string, consisting of 0xFFs.
     *
     * @param length The length of the padding string in bytes.
     * @return The padding string.
     */
    private static byte[] generatePaddingString(int length) {

        byte[] paddingString = new byte[length];
        for (int i = 0; i < paddingString.length; i++) {
            paddingString[i] = PADDING_STRING_BYTE;
        }

        return paddingString;
    }

    /**
     * Apply SHA-256 hash function to {@code data} and return result.
     * @param data The data on which the hash function is applied.
     * @return The hash digest.
     */
    private static byte[] SHA256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is not available.", e);
        }
    }
}
