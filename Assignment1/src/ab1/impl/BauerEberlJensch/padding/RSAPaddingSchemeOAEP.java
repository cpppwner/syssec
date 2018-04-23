package ab1.impl.BauerEberlJensch.padding;

import ab1.RSA;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * RSA OAEP Padding scheme implementation.
 *
 * <p>
 *     Implementation is based on https://www.ietf.org/rfc/rfc3447.txt
 * </p>
 */
public class RSAPaddingSchemeOAEP implements RSAPaddingScheme {

    private static final byte IDENTIFIER = 0x42;

    private static final String HASH_FUNCTION_NAME = "SHA-256";

    private final RSA.PublicKey publicKey;
    private final RSA.PrivateKey privateKey;
    private final int hashFunctionLength;
    private final SecureRandom random = new SecureRandom();

    public RSAPaddingSchemeOAEP(RSA.PublicKey publicKey, RSA.PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        try {
            hashFunctionLength = MessageDigest.getInstance(HASH_FUNCTION_NAME).getDigestLength();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    @Override
    public byte getIdentifier() {
        return IDENTIFIER;
    }

    @Override
    public int maximumPlainTextLength() {
        // the computation below is equal to floor(publicKey.getN().bitLength() / 8.0) - padding bytes
        // but since it's just integer operations probably faster
        return modulLengthInBytes() - 2 * hashFunctionLength - 2;
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
        // first encode the message
        byte[] message = encodeMessage(data);

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

    /**
     * Encode the OAEP padded message which will be encrypted.
     *
     * @data The data to encode and encrypt.
     * @return Encoded message, which can be encrypted.
     */
    private byte[] encodeMessage(byte[] data) {

        // If the label L is not provided, let L be the empty string.
        // Let lHash = Hash(L)
        byte[] lHash = SHA256("".getBytes());

        // generate the octet string PS (Note: The length might be 0).
        byte[] ps = new byte[maximumPlainTextLength() - data.length];

        // concatenate lHash || PS || 0x01 || M
        byte[] dataBlock = generateDataBlock(lHash, ps, data);

        // Generate a random octet string seed of length hLen.
        byte[] seed = new byte[hashFunctionLength];
        random.nextBytes(seed);

        // Let dbMask = MGF(seed, k - hLen - 1)
        byte[] dataBlockMask = MGF1(seed, modulLengthInBytes() - hashFunctionLength - 1);

        // internal sanity check
        if (dataBlock.length != dataBlockMask.length) {
            throw new IllegalStateException("dataBlock.length (=" + dataBlock.length + ") != dataBlockMask.length (=" + dataBlockMask.length + ")");
        }

        // Let maskedDB = DB \xor dbMask
        // xor data block and data block mask (re-use dataBlock instead of duplicating into maskedDB)
        for (int i = 0; i < dataBlockMask.length; i++) {
            dataBlock[i] ^= dataBlockMask[i];
        }

        // Let seedMask = MGF(maskedDB, hLen)
        byte[] seedMask = MGF1(dataBlock, hashFunctionLength);

        // Let maskedSeed = seed \xor seedMask.
        // xor seed with seedMask (store result in seed)
        for (int i = 0; i < seed.length; i++) {
            seed[i] ^= seedMask[i];
        }

        // generate the message to encrypt
        byte[] message = new byte[1 + seed.length + dataBlock.length];
        message[0] = 0x00;
        System.arraycopy(seed, 0, message, 1, seed.length);
        System.arraycopy(dataBlock, 0, message, 1 + seed.length, dataBlock.length);

        return message;
    }

    private byte[] generateDataBlock(byte[] lHash, byte[] ps, byte[] data) {

        byte[] dataBlock = new byte[lHash.length + ps.length + data.length + 1];
        System.arraycopy(lHash, 0, dataBlock, 0, lHash.length);
        if (ps.length > 0) {
            System.arraycopy(ps, 0, dataBlock, lHash.length, ps.length);
        }
        dataBlock[lHash.length + ps.length] = 0x01;
        System.arraycopy(data, 0, dataBlock, lHash.length + ps.length + 1, data.length);

        return dataBlock;
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

        return decodeMessage(result);
    }

    /**
     * Decode the OAEP padded message.
     * @param data Previously decrypted message.
     * @return Plain message as passed to the {@link #encrypt(byte[])} method.
     */
    private byte[] decodeMessage(byte[] data) {

        // If the label L is not provided, let L be the empty string.
        // Let lHash = Hash(L)
        byte[] lHash = SHA256("".getBytes());

        // Separate the encoded message EM into a single octet Y, an octet
        // string maskedSeed of length hLen, and an octet string maskedDB
        // of length k - hLen - 1 as
        byte y = data[0];
        // from encoding we know that y must be zero
        if (y != 0) {
            // message was changed - just return an empty byte array
            return new byte[0];
        }

        // get out the masked seed and the masked data block
        byte[] maskedSeed = Arrays.copyOfRange(data, 1, 1 + hashFunctionLength);
        byte[] maskedDataBlock = Arrays.copyOfRange(data, 1 + hashFunctionLength, data.length);

        // Let seedMask = MGF(maskedDB, hLen).
        byte[] seedMask = MGF1(maskedDataBlock, hashFunctionLength);

        // Let seed = maskedSeed \xor seedMask.
        byte[] seed = Arrays.copyOf(maskedSeed, maskedSeed.length);
        for (int i = 0; i < seed.length; i++) {
            seed[i] ^= seedMask[i];
        }

        // Let dbMask = MGF(seed, k - hLen - 1).
        byte[] dataBlockMask = MGF1(seed, modulLengthInBytes() - hashFunctionLength - 1);

        // Let DB = maskedDB \xor dbMask.
        byte[] dataBlock = Arrays.copyOf(maskedDataBlock, maskedDataBlock.length);
        for (int i = 0; i < dataBlock.length; i++) {
            dataBlock[i] ^= dataBlockMask[i];
        }

        // Separate DB into an octet string lHash' of length hLen, a
        // (possibly empty) padding string PS consisting of octets with
        // hexadecimal value 0x00, and a message M as
        byte[] decodedLHash = Arrays.copyOfRange(dataBlock, 0, hashFunctionLength);
        if (!Arrays.equals(decodedLHash, lHash)) {
            // lHash is wrong
            return new byte[0];
        }

        // check that PS (if not empty is only zeros)
        int offset = hashFunctionLength;
        while (dataBlock[offset] == 0) {
            // skip padding string zero-bytes (if any)
            offset++;
        }

        // the first byte after the padding string must 0x01
        if (dataBlock[offset] != 0x01) {
            // wrong padding byte
            return new byte[0];
        }

        // now let's return the real message
        return Arrays.copyOfRange(dataBlock, offset + 1, dataBlock.length);
    }

    public static boolean isOAEPPaddingScheme(byte[] cipher) {
        return cipher[0] == IDENTIFIER;
    }

    private int modulLengthInBytes() {
        return publicKey.getN().bitLength() /  8;
    }

    /**
     * Message generation function.
     */
    private byte[] MGF1(byte[] seed, int desiredLength) {
        int hLen = hashFunctionLength;

        byte[] mask = new byte[desiredLength];
        byte[] temp = new byte[seed.length + 4];

        System.arraycopy(seed, 0, temp, 4, seed.length);

        for (int offset = 0, i = 0; offset < desiredLength; offset += hLen, i++) {
            temp[0] = (byte) (i >>> 24);
            temp[1] = (byte) (i >>> 16);
            temp[2] = (byte) (i >>> 8);
            temp[3] = (byte) i;
            int remaining = desiredLength - offset;
            System.arraycopy(SHA256(temp), 0, mask, offset, remaining < hLen ? remaining : hLen);
        }

        return mask;
    }

    /**
     * SHA-256 wrapper function.
     */
    private byte[] SHA256(byte[] data) {
        try {
            return MessageDigest.getInstance(HASH_FUNCTION_NAME).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available.", e);
        }
    }
}
