package ab1.impl.BauerEberlJensch;

import ab1.RSA;
import ab1.impl.BauerEberlJensch.padding.RSAPaddingScheme;
import ab1.impl.BauerEberlJensch.padding.RSAPaddingSchemeOAEP;
import ab1.impl.BauerEberlJensch.padding.RSAPaddingSchemePKCS1;

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

            // calculate N = p * q
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

    private static BigInteger generateEncryptionExponent(BigInteger phi) {
        BigInteger e = MAGIC;

        while (!phi.gcd(e).equals(BigInteger.ONE)) {
            e = e.add(TWO);
        }

        return e;
    }

    private static BigInteger generateDecryptionExponent(BigInteger phi, BigInteger e) {

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
                ? new RSAPaddingSchemeOAEP(getPublicKey(), getPrivateKey())
                : new RSAPaddingSchemePKCS1(getPublicKey(), getPrivateKey());

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
            byte[] chunk = Arrays.copyOfRange(data, chunkIndexStart, chunkIndexEnd);

            // encode the chunk
            byte[] cipherChunk = paddingScheme.encrypt(chunk);

            // store encrypted chunk in final cipher
            // NOTE: each output block has a fixed length of cipherChunkSize with leading zeros.
            int cipherIndex = ((i + 1) * cipherChunkSize) - cipherChunk.length + 1;
            System.arraycopy(cipherChunk, 0, cipher, cipherIndex, cipherChunk.length);
        }

        return cipher;
    }

    @Override
    public byte[] decrypt(byte[] data) {

        RSAPaddingScheme paddingScheme;
        if (RSAPaddingSchemePKCS1.isPKCS1PaddingScheme(data)) {
            paddingScheme = new RSAPaddingSchemePKCS1(getPublicKey(), getPrivateKey());
        } else if (RSAPaddingSchemeOAEP.isOAEPPaddingScheme(data)) {
            paddingScheme = new RSAPaddingSchemeOAEP(getPublicKey(), getPrivateKey());
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
            byte[] messageChunk = paddingScheme.decrypt(chunk);

            // store decrypted message in final message
            if (message.length - messageOffset > messageChunk.length) {
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

    @Override
    public byte[] sign(byte[] message) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Boolean verify(byte[] message, byte[] signature) {
        // TODO Auto-generated method stub
        return null;
    }

    private static byte[] encrypt(byte[] message, BigInteger exp, BigInteger modulus) {

        // now do the real encryption
        BigInteger c = new BigInteger(1, message).modPow(exp, modulus);

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
}
