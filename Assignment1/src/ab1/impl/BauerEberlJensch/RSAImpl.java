package ab1.impl.BauerEberlJensch;

import ab1.RSA;
import ab1.impl.BauerEberlJensch.padding.RSAPaddingScheme;
import ab1.impl.BauerEberlJensch.padding.RSAPaddingSchemeOAEP;
import ab1.impl.BauerEberlJensch.padding.RSAPaddingSchemePKCS1;
import ab1.impl.BauerEberlJensch.signature.PKCS1;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implementation of the {@link RSA} interface.
 *
 * @author Christian Bauer
 * @author Stefan Eberl
 * @author Walter Jensch
 */
public class RSAImpl implements RSA {

    /**
     * The magic number to start with, which is 2^16+1 (see slides)
     */
    private static final BigInteger MAGIC = BigInteger.valueOf(65537);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;

    @Override
    public void init(int n) {

        // generate two distinct primes
        // this is required to further calculate the encryption/decryption exponents
        // and the modulus.
        SecureRandom random = new SecureRandom();

        BigInteger N;
        BigInteger p;
        BigInteger q;

        do {
            // choose two distinct prime numbers
            p = BigInteger.probablePrime(n / 2, random);
            do {
                q = BigInteger.probablePrime(n / 2, random);
            } while (p.equals(q));

            // calculate N = p * q - N is the modulus used for encryption/decryption
            // NOTE: the slides use lower case n, but that's already in use
            // therefore use upper case
            N = p.multiply(q);
        } while (N.bitLength() != n);

        // NOTE: In PKCS#1 v2.0 this was changed to lcm(p - 1, q - 1)
        // We still implement the old way
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // generate encryption exponent
        BigInteger e = generateEncryptionExponent(phi);

        // generate decryption exponent
        BigInteger d = generateDecryptionExponent(phi, e);

        // build up public & private keys
        publicKey = new PublicKey(N, e);
        privateKey = new PrivateKey(N, d);
    }

    /**
     * Generate the encryption exponent
     * @param phi Phi, which is (p -1) * (q - 1) where, p and q are non-identical prime numbers.
     * @return Encryption exponent.
     */
    private static BigInteger generateEncryptionExponent(BigInteger phi) {
        BigInteger e = MAGIC;

        while (!phi.gcd(e).equals(BigInteger.ONE)) {
            // phi is an even number, therefore incrementing by one
            // does not make sense, since GCD will not be one, if e
            // is also even.
            e = e.add(TWO);
        }

        return e;
    }

    /**
     * Generate decryption exponent.
     *
     * @param phi Phi, which is (p -1) * (q - 1) where, p and q are non-identical prime numbers.
     * @param e Encryption exponent generated via {@link #generateEncryptionExponent(BigInteger)}
     * @return Decryption exponent.
     */
    private static BigInteger generateDecryptionExponent(BigInteger phi, BigInteger e) {

        // decryption exponent must be mod inverse of encryption exponent
        return e.modInverse(phi);
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public byte[] encrypt(byte[] data, boolean activateOAEP) {

        RSAPaddingScheme paddingScheme = activateOAEP
                ? new RSAPaddingSchemeOAEP(getPublicKey().getN().bitLength())
                : new RSAPaddingSchemePKCS1(getPublicKey().getN().bitLength());

        // maximum length of plain text message & cipher text message
        int messageChunkSize = paddingScheme.maximumPlainTextLength();
        int cipherChunkSize = paddingScheme.maximumCipherTextLength();

        // compute the number of chunks we can expect
        // this is basically ceil(data.length / 8.0)
        int numChunks = (data.length % messageChunkSize) == 0
                ? data.length / messageChunkSize
                : (data.length / messageChunkSize) + 1;

        byte[] cipher = new byte[numChunks * cipherChunkSize + 1];
        cipher[0] = paddingScheme.getIdentifier();

        for (int i = 0; i < numChunks; i++) {
            // get the chunk that shall be encrypted
            int chunkIndexStart = i * messageChunkSize;
            int chunkIndexEnd = Math.min((i + 1) * messageChunkSize, data.length);

            // encode the chunk
            byte[] message = paddingScheme.encode(Arrays.copyOfRange(data, chunkIndexStart, chunkIndexEnd));

            // and encrypt the previously encoded message
            byte[] cipherChunk = encrypt(message, publicKey.getE(), publicKey.getN());

            // store encrypted chunk in final cipher
            // NOTE: each output block has a fixed length of cipherChunkSize with leading zeros.
            int cipherIndex = ((i + 1) * cipherChunkSize) - cipherChunk.length + 1;
            System.arraycopy(cipherChunk, 0, cipher, cipherIndex, cipherChunk.length);
        }

        return cipher;
    }

    /**
     * Utility function to encrypt a given message.
     *
     * @param message The message to encrypt.
     * @param exponent The exponent used for encryption.
     * @param modulus Modulus used for encryption.
     * @return Encrypted message.
     */
    private static byte[] encrypt(byte[] message, BigInteger exponent, BigInteger modulus) {
        // now do the real encryption
        BigInteger c = new BigInteger(1, message).modPow(exponent, modulus);

        byte[] cipher = c.toByteArray();
        if (c.bitLength() % 8 == 0 && c.bitLength() / 8 != cipher.length) {
            // sign bit - leading 0
            cipher = Arrays.copyOfRange(cipher, 1, cipher.length);
        }

        int maximumCipherTextLength = modulus.bitLength() / 8;
        if (cipher.length > maximumCipherTextLength) {
            // just a sanity check
            throw new IllegalStateException("cipher too long (got=" + cipher.length + "; expected=" +maximumCipherTextLength + ")");
        }

        return cipher;
    }

    @Override
    public byte[] decrypt(byte[] data) {

        RSAPaddingScheme paddingScheme;
        if (RSAPaddingSchemePKCS1.isPKCS1PaddingScheme(data)) {
            paddingScheme = new RSAPaddingSchemePKCS1(getPrivateKey().getN().bitLength());
        } else if (RSAPaddingSchemeOAEP.isOAEPPaddingScheme(data)) {
            paddingScheme = new RSAPaddingSchemeOAEP(getPrivateKey().getN().bitLength());
        } else {
            throw new IllegalArgumentException("Unknown padding scheme.");
        }

        int cipherChunkSize = paddingScheme.maximumCipherTextLength();

        // compute the number of chunks we can expect
        // this is basically ceil(data.length / 8.0)
        int numChunks = ((data.length - 1) % cipherChunkSize) == 0
                ? (data.length - 1) / cipherChunkSize
                : ((data.length - 1) / cipherChunkSize) + 1;

        // pre-allocate decrypted message, using worst case assumption
        byte[] message = new byte[numChunks * paddingScheme.maximumPlainTextLength()];
        int messageOffset = 0; // offset of next decrypted chunk

        for (int i = 0; i < numChunks; i++) {
            // get the chunk that shall be decrypted
            int chunkIndexStart = 1 + (i * cipherChunkSize);
            int chunkIndexEnd = Math.min(1 + ((i + 1) * cipherChunkSize), data.length);
            byte[] chunk = Arrays.copyOfRange(data, chunkIndexStart, chunkIndexEnd);

            // decrypt previously obtained chunk
            byte[] decryptedChunk = decrypt(chunk, getPrivateKey().getD(), getPrivateKey().getN());

            // decode using padding scheme
            byte[] messageChunk = paddingScheme.decode(decryptedChunk);

            // store decrypted message in final message
            if (messageOffset + messageChunk.length <= message.length) {
                System.arraycopy(messageChunk, 0, message, messageOffset, messageChunk.length);
            } else {
                // huh - need to reallocate the final message
                // just double the new length
                message = Arrays.copyOf(message, message.length * 2);
            }

            // adjust the offset
            messageOffset += messageChunk.length;
        }

        // truncate the decrypted message to the number of bytes
        // which were actually decrypted.
        return Arrays.copyOf(message, messageOffset);
    }

    /**
     * Utility function to decrypt a given message.
     *
     * @param data The cipher to decrypt.
     * @param exponent The exponent used for decryption.
     * @param modulus Modulus used for decryption.
     * @return Decrypted message.
     */
    private static byte[] decrypt(byte[] data, BigInteger exponent, BigInteger modulus) {

        // internal sanity check - ensure the data length
        int maximumCipherTextLength = (modulus.bitLength() + 7) / 8;
        if (data.length > maximumCipherTextLength) {
            throw new IllegalArgumentException("data.length is invalid");
        }

        // decrypt the chunk
        BigInteger decrypted = new BigInteger(1, data).modPow(exponent, modulus);
        byte[] decryptedData = decrypted.toByteArray();
        if ((decrypted.bitLength() % 8) == 0 && decrypted.bitLength() / 8 != decryptedData.length) {
            // sign bit - leading 0
            decryptedData = Arrays.copyOfRange(decryptedData, 1, decryptedData.length);
        }

        // build up the resulting message
        byte[] result = new byte[modulus.bitLength() / 8];
        System.arraycopy(decryptedData, 0, result, result.length - decryptedData.length, decryptedData.length);
        return result;
    }

    @Override
    public byte[] sign(byte[] message) {

        // encode the message
        int expectedMessageLength = getPrivateKey().getN().bitLength() / 8;
        byte[] encodedMessage = PKCS1.encode(message, expectedMessageLength);

        // and encrypt encoded message using the private key
        return encrypt(encodedMessage, getPrivateKey().getD(), getPrivateKey().getN());
    }

    @Override
    public Boolean verify(byte[] message, byte[] signature) {

        // decrypt the signature using the public key
        byte[] decrypted = decrypt(signature, getPublicKey().getE(), getPublicKey().getN());

        // verify the decrypted message against the plain text message.
        return PKCS1.verify(decrypted, message);
    }
}
