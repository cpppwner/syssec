package ab2.impl.Eberl;

import ab2.ElGamal;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

/**
 * Implementation of ElGamal.
 *
 * <p>
 *     The implemented algorithm is based on the following notes: http://www.maths.qmul.ac.uk/~bill/MTH6115/cn9.pdf.
 * </p>
 */
public class ElGamalImpl implements ElGamal {

    /**
     * The minimum number of padding bytes when encrypting data.
     *
     * <p>
     *     At least the {@link #PADDING_SEPARATOR} must be added.
     * </p>
     */
    private static final int MIN_NUM_PADDING_BYTES = 1;

    /**
     * Padding byte.
     */
    private static final byte PADDING_BYTE = 0x00;
    /**
     * Byte value used to separate the padding bytes from plain text message.
     */
    private static final byte PADDING_SEPARATOR = 0x01;

    /**
     * Default certainty for prime checking.
     */
    private static final int DEFAULT_PRIME_CERTAINTY = 100;

    /**
     * {@code 2} expressed as {@link BigInteger}.
     */
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /**
     * {@code -1} expressed as {@link BigInteger}.
     */
    private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

    /**
     * The ElGamal public key.
     */
	private PublicKey publicKey = null;
    /**
     * The ElGamal private key.
     */
	private PrivateKey privateKey = null;

    /**
     * Secure random number generator.
     */
	private final SecureRandom secureRandom = new SecureRandom();

    @Override
	public void init(int n) {

	    // 1. compute a prime number p (bit length == n)
        // based on number theory, using Germain primes is quite nice for doing so
        BigInteger germainPrime;
        BigInteger safePrime;
        BigInteger twoPowGermainPrime;

        // The algorithm implemented below is based on the suggestion of Cramer Shoup,
        // * "Signature Schemes based on the strong RSA assumption", 2000.
        do {
            // Theory: A prime number p is a Germain prime (named after Sophie Germain) if
            // q = 2 * p + 1 is also a prime number.
            do {
                germainPrime = BigInteger.probablePrime(n - 1, secureRandom);
                safePrime = germainPrime.shiftLeft(1).add(BigInteger.ONE);
            } while (safePrime.bitLength() != n || !safePrime.isProbablePrime(DEFAULT_PRIME_CERTAINTY));
            twoPowGermainPrime = TWO.modPow(germainPrime, safePrime);
        } while (!twoPowGermainPrime.equals(BigInteger.ONE) && !twoPowGermainPrime.subtract(safePrime).equals(MINUS_ONE));

        BigInteger p = safePrime;
        BigInteger q = germainPrime;

        // 2. compute a primitive root g mod p

        // "Proposition 24 let (q, p) be a Sophie Germain pair. Suppose that 1 < x < p−2. Then
        // x is a primitive root mod p if and only if x^q ≡ -1 (mod p)."
        BigInteger pMinusTwo = p.subtract(TWO);
        BigInteger g;
        do {
            g = new BigInteger(n, secureRandom);
        } while (isValueNotInRange(g, TWO, pMinusTwo) || !isPrimitiveRoot(g, q, p));

        // 3. generate a random number "a" in range [1, p - 1)
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger a;
        do  {
            a = new BigInteger(n, secureRandom);
        } while (isValueNotInRange(a, BigInteger.ONE, pMinusOne));

        // compute h = g^a mod p
        // in ElGamal.PublicKey h is equivalent to e
        BigInteger h = g.modPow(a, p);

        // create public key based on previously computed values
        publicKey = new ElGamal.PublicKey(p, g, h);

        // create private key based on previously computed values
        privateKey = new ElGamal.PrivateKey(p, g, a);
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
	public byte[] encrypt(byte[] data) {

        // first split the message into chunks
        List<byte[]> chunks = splitIntoChunks(data, getMaxPlainTextChunkLength());

        // encrypt each chunk separately
        List<byte[]> cipherChunks = new ArrayList<>(chunks.size());
        for (byte[] chunk : chunks) {
            byte[] cipherChunk = encryptChunk(chunk);
            cipherChunks.add(cipherChunk);
        }

        // merge previously encrypted chunks into one big cipher
        byte[] cipher = mergeCiphers(cipherChunks);

        // sanity check to verify that the algorithm works as expected
        if (cipher.length != chunks.size() * getCipherTextChunkLength()) {
            throw new IllegalStateException("Algorithm not implemented correctly.");
        }

        // return the cipher
        return cipher;
	}

    @Override
	public byte[] decrypt(byte[] data) {

	    // first split the cipher into chunks
        List<byte[]> chunks = splitIntoChunks(data, getCipherTextChunkLength());

        // decrypt each chunk separately
        List<byte[]> plainTextChunks = new ArrayList<>(chunks.size());
        for (byte[] chunk : chunks) {
            byte[] plainTextChunk = decryptChunk(chunk);
            plainTextChunks.add(plainTextChunk);
        }

        // merge previously decrypted chunks inot one big plain text data
        return mergePlainTextChunks(plainTextChunks);
	}

    @Override
	public byte[] sign(byte[] message) {

        // choose a random number k in range [2, p-1)
        // such that gcd(k, p - 1) = 1
        BigInteger z1;
        BigInteger z2;

        do {
            BigInteger pMinusOne = privateKey.getP().subtract(BigInteger.ONE);
            BigInteger k;
            do {
                k = new BigInteger(privateKey.getP().bitLength(), secureRandom);
            } while (isValueNotInRange(k, TWO, pMinusOne) || !k.gcd(pMinusOne).equals(BigInteger.ONE));

            // compute z1 = g^k (mod p)
            z1 = privateKey.getG().modPow(k, privateKey.getP());

            // compute inverse of k (mod p - 1) -> required for next part of the signature pair
            BigInteger l = k.modInverse(pMinusOne);
            // compute a * z1 (mod p - 1) -> required for z2
            // Note: a (from the pdf) is privateKey.getD() in our case
            BigInteger aTimesZ1 = privateKey.getD().multiply(z1).mod(pMinusOne);

            // compute z2 = (H(message) - a * z1) * k^-1 mod p - 1
            z2 = (((hash(message).mod(pMinusOne)).subtract(aTimesZ1)).mod(pMinusOne)).multiply(l).mod(pMinusOne);
        } while (z2.equals(BigInteger.ZERO)); // Wikipedia says to start over again, if z2 is zero

        // the computed pair (z1, z2) is the signature
        // allocate the final byte[] and store (z1, z2) in this array
        byte[] signature = new byte[getCipherTextChunkLength()];

        // copy y1 and y2 into cipher chunk
        byte[] z1Data = toByteArray(z1);
        byte[] z2Data = toByteArray(z2);
        System.arraycopy(z1Data, 0, signature, signature.length / 2 - z1Data.length, z1Data.length);
        System.arraycopy(z2Data, 0, signature, signature.length - z2Data.length, z2Data.length);

        return signature;
	}

    @Override
	public Boolean verify(byte[] message, byte[] signature) {

        // check that signature has even length
        if (signature.length != getCipherTextChunkLength()) {
            throw new IllegalArgumentException("invalid signature length");
        }

        // extract the tuple (z1, z2) from signature
        BigInteger z1 = new BigInteger(1, Arrays.copyOfRange(signature, 0, signature.length / 2));
        BigInteger z2 = new BigInteger(1, Arrays.copyOfRange(signature, signature.length / 2, signature.length));

        BigInteger pMinusOne = publicKey.getP().subtract(BigInteger.ONE);

        // ensure ranges of z1 and z2
        // if z1 or z2 is out of range, then the signature is already invalid

        // for z1 the range is: 0 < z1 < p (or slightly re-written: 1 <= z1 <= p - 1)
        if (z1.compareTo(BigInteger.ONE) < 0 || z1.compareTo(pMinusOne) > 0) {
            return false;
        }

        // for z2 the range is: 0 < z2 < p - 1 (or slightly re-written: 1 <= z1 < p - 1)
        if (z2.compareTo(BigInteger.ONE) < 0 || z1.compareTo(pMinusOne) >= 0) {
            return false;
        }

        // verify that
        // h^(z1) * z1^(z2) == g^(H(message)) (mod p)
        // note that h is used in the implementation note (PDF)
        // in our case h is equal to publicKey.getE()
        BigInteger rhs = publicKey.getG().modPow(hash(message), publicKey.getP());
        BigInteger hPowZ1 = publicKey.getE().modPow(z1, publicKey.getP());
        BigInteger z1PowZ2 = z1.modPow(z2, publicKey.getP());
        BigInteger lhs = hPowZ1.multiply(z1PowZ2).mod(publicKey.getP());

        return lhs.equals(rhs);
	}

    /**
     * Utility method to check if given {@code value} is not in range [lower, upper).
     *
     * @param value The value to check whether it's in allowed range or.
     * @param lowerBound The lower bound for the range check (lower bound is included).
     * @param upperBound The upper bound for the range check (upper bound is excluded).
     * @return {@code true} if {@code value} is not in range, {@code false} otherwise.
     */
    private static boolean isValueNotInRange(BigInteger value, BigInteger lowerBound, BigInteger upperBound) {

        return value.compareTo(lowerBound) < 0 || value.compareTo(upperBound) >= 0;
    }

    /**
     * Utility method to check if a given number g is a primitive root.
     *
     * <p>
     *     {@code g} is a primitive root if and only if g^q = -1 (mod p).
     * </p>
     *
     * @param g The number to check if it's a primitive root.
     * @param q Exponent.
     * @param p Modulus.
     * @return {@code true} if {@code g} is a primitive root, {@code false} otherwise.
     */
    private static boolean isPrimitiveRoot(BigInteger g, BigInteger q, BigInteger p) {

        BigInteger gPowTwo = g.modPow(TWO, p);
        BigInteger gPowQ = g.modPow(q, p);

        return !gPowTwo.equals(BigInteger.ONE) && !gPowQ.equals(BigInteger.ONE);
    }

    /**
     * Split the given {@code data} into separate chunks.
     *
     * <p>
     *     Each chunk has a maximum length of {@code maxChunkLength}.
     * </p>
     *
     * @param data The original data to split into chunks.
     * @param maxChunkLength The maximum length in bytes for a single chunk.
     * @return The split chunks.
     */
    private static List<byte[]> splitIntoChunks(byte[] data, int maxChunkLength) {

        // if the incoming data is empty, then we extract exactly one chunk, which is empty
        if (data.length == 0) {
            return Collections.singletonList(data);
        }

        // pre-compute the number of chunks which are expected
        int numChunks = data.length % maxChunkLength == 0
                ? data.length / maxChunkLength
                : (data.length / maxChunkLength) + 1;

        // split up the data into chunks
        List<byte[]> chunks = new ArrayList<>(numChunks);
        for (int i = 0; i < numChunks; i++) {
            int chunkStartIndex = i * maxChunkLength;
            int chunkEndIndex = Math.min(data.length, (i + 1) * maxChunkLength);

            byte[] chunk = Arrays.copyOfRange(data, chunkStartIndex, chunkEndIndex);
            chunks.add(chunk);
        }

        return chunks;
    }

    /**
     * Encrypt a chunk using the ElGamal algorithm.
     *
     * <p>
     *     {@code chunk.length} must be less than or equal to {@link #getMaxPlainTextChunkLength()}.
     * </p>
     *
     * @param chunk The chunk data to encrypt.
     * @return Encrypted (cipher) chunk.
     */
    private byte[] encryptChunk(byte[] chunk) {

        if (chunk.length > getMaxPlainTextChunkLength()) {
            throw new IllegalArgumentException("Chunk too long");
        }

        // generate a random number k in range [1, p)
        BigInteger k;
        do  {
            k = new BigInteger(publicKey.getP().bitLength(), secureRandom);
        } while (isValueNotInRange(k, BigInteger.ONE, publicKey.getP()));

        // now compute y1 = g^k mod p
        BigInteger y1 = publicKey.getG().modPow(k, publicKey.getP());

        // and y2 = chunk * h ^ k (Note: h is used in the paper and is equivalent to e in ElGamal.PublicKey)
        byte[] paddedChunk = pad(chunk, getMaxPlainTextChunkLength() + MIN_NUM_PADDING_BYTES);
        BigInteger y2 = new BigInteger(1, paddedChunk)
                .multiply(publicKey.getE().modPow(k, publicKey.getP()))
                .mod(publicKey.getP());

        // build up the cipher chunk, which stores (y1, y2)
        // Note: y1 and/or y2 might have leading zeros, if they are too short
        byte[] cipher = new byte[getCipherTextChunkLength()];

        // copy y1 and y2 into cipher chunk
        byte[] y1Data = toByteArray(y1);
        byte[] y2Data = toByteArray(y2);
        System.arraycopy(y1Data, 0, cipher, cipher.length / 2 - y1Data.length, y1Data.length);
        System.arraycopy(y2Data, 0, cipher, cipher.length - y2Data.length, y2Data.length);

        return cipher;
    }

    /**
     * Pad the given chunk to reach the maximum length.
     *
     * <p>
     *     The padding scheme is quite simple and not really secure.
     *     The padded string is {@link #PADDING_BYTE} || {@link #PADDING_SEPARATOR} || chunk.
     * </p>
     *
     * @param chunk The chunk to pad.
     * @return The padded chunk.
     */
    private static byte[] pad(byte[] chunk, int paddedChunkLength) {

        int numPaddingBytes = paddedChunkLength - chunk.length - 1;

        // prepend the padding byte
        byte[] paddedChunk = new byte[paddedChunkLength];
        for (int i = 0; i < numPaddingBytes; i++) {
            paddedChunk[i] = PADDING_BYTE;
        }

        paddedChunk[numPaddingBytes] = PADDING_SEPARATOR;

        // copy chunk data
        System.arraycopy(chunk, 0, paddedChunk, numPaddingBytes + 1, chunk.length);

        return paddedChunk;
    }

    /**
     * Merge cipher chunks into a single cipher text.
     *
     * <p>
     *     Each cipher chunk in the given {@code ciphers} must exactly
     *     {@link #getCipherTextChunkLength()} bytes in length.
     * </p>
     *
     * @param ciphers The cipher chunks to merge.
     * @return A single cipher text.
     */
    private byte[] mergeCiphers(List<byte[]> ciphers) {

        int cipherTextChunkLength = getCipherTextChunkLength();

        // pre-allocate the resulting cipher
        byte[] cipher = new byte[ciphers.size() * cipherTextChunkLength];

        // copy the cipher chunks into resulting cipher
        int offset = 0;
        for (byte[] cipherChunk : ciphers) {

            // sanity check
            if (cipherChunk.length != cipherTextChunkLength) {
                throw new IllegalStateException("Cipher text chunk too small");
            }

            System.arraycopy(cipherChunk, 0, cipher, offset, cipherTextChunkLength);
            offset += cipherTextChunkLength;
        }

        return cipher;
    }

    /**
     * Decrypt the given cipher chunk.
     *
     * @param chunk The cipher chunk to decrypt.
     * @return Plain text message or {@code null} if cipher has been compromised.
     */
    private byte[] decryptChunk(byte[] chunk) {

        // split up the chunk into y1 and y2 (see encryption)
        if ((chunk.length % 2) != 0) {
            // internal check
            throw new IllegalArgumentException("cipher chunk length must be multiple of 2");
        }

        // extract y1 and y2
        BigInteger y1 = new BigInteger(1, Arrays.copyOfRange(chunk, 0, chunk.length / 2));
        BigInteger y2 = new BigInteger(1, Arrays.copyOfRange(chunk, chunk.length / 2, chunk.length));

        // compute the shared secret y1^a (mod p)
        BigInteger secret = y1.modPow(privateKey.getD(), privateKey.getP());

        // compute the inverse of secret (mod p)
        BigInteger inverseSecret = secret.modInverse(privateKey.getP());

        // compute padded message by multiplying y2 with inverseSecret (mod p)
        byte[] paddedMessage = toByteArray(y2.multiply(inverseSecret).mod(privateKey.getP()));

        return unPad(paddedMessage);
    }

    /**
     * Un-pad the given chunk to get out the original plain text message.
     *
     * <p>
     *     The padding scheme is quite simple and not really secure.
     *     The padded string is {@link #PADDING_BYTE} || {@link #PADDING_SEPARATOR} || chunk.
     * </p>
     *
     * @param chunk The chunk to un-pad.
     * @return The plain text message.
     */
    private static byte[] unPad(byte[] chunk) {

        // search for padding/message separator byte
        int separatorByteIndex = -1;
        for (int i = 0; i < chunk.length; i++) {
            if (chunk[i] == PADDING_SEPARATOR) {
                // found the separator byte
                separatorByteIndex = i;
                break;
            }
        }

        // if no separator was found the cipher has been compromised
        if (separatorByteIndex < 0) {
            // just return null in this case
            return null;
        }

        // separator has been found
        // ensure that all bytes up to (excluding) the separator are padding bytes
        for (int i = 0; i < separatorByteIndex; i++) {
            if (chunk[i] != PADDING_BYTE) {
                // not a padding byte -> cipher has been compromised
                return null;
            }
        }

        if (separatorByteIndex + 1 == chunk.length) {
            return new byte[0]; // empty message
        }

        // copy everything in range [separator + 1, end)
        // which is the plain text message
        return Arrays.copyOfRange(chunk, separatorByteIndex + 1, chunk.length);
    }

    /**
     * Merge plain text chunks into one plain text message.
     *
     * @param plainTextChunks The chunks to merge.
     * @return Merged chunks.
     */
    private static byte[] mergePlainTextChunks(List<byte[]> plainTextChunks) {

        // first check if any chunk is null and if so, return an empty array in this case
        if (plainTextChunks.stream().anyMatch(Objects::isNull)) {
            // cipher has been compromised
            return new byte[0];
        }

        // pre-calculate the final plain text length
        // this is the sum of the chunk lengths
        int plainTextLength = plainTextChunks.stream().mapToInt(chunk -> chunk.length).sum();

        // allocate the plain text message
        byte[] plainText = new byte[plainTextLength];

        // copy all plain text chunks into plain text
        int offset = 0;
        for (byte[] plainTextChunk : plainTextChunks) {
            System.arraycopy(plainTextChunk, 0, plainText, offset, plainTextChunk.length);
            offset += plainTextChunk.length;
        }

        return plainText;
    }

    /**
     * Get the maximum plain text chunk length in bytes, based on the module prime p.
     *
     * <p>
     *     The maximum plain text chunk length is the length in bytes that can be encrypted at once.
     * </p>
     *
     * @return The maximum plain text chunk length in bytes.
     */
    private int getMaxPlainTextChunkLength() {

        return (publicKey.getP().bitLength() / 8) - 1;
    }

    /**
     * Get the cipher text chunk length in bytes.
     *
     * @return The cipher text chunk length in bytes.
     */
    private int getCipherTextChunkLength() {

        // the computation below is equal to ceil(publicKey.getP().bitLength() / 8.0)
        // but since it's just integer operations probably faster
        return ((publicKey.getP().bitLength() + 7) / 8) * 2;
    }

    /**
     * Apply a cryptographic/collision resistant hash function on {@code message}.
     *
     * <p>
     *     For the purpose of this implementation SHA-256 will be used.
     * </p>
     *
     * @param message The plain text message to hash.
     * @return Hashed value of given {@code message}.
     */
    private BigInteger hash(byte[] message) {

        // create the message digest
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available.");
        }

        byte[] hashedMessage = digest.digest(message);

        return new BigInteger(1, hashedMessage);
    }

    /**
     * Utility method to convert the given {@link BigInteger} to a byte array.
     *
     * <p>
     *     This method uses {@link BigInteger#toByteArray()} and strips a leading
     *     {@code 0x00}, indicating a sign bit.
     * </p>
     *
     * @param integer {@link BigInteger} for which to get {@code byte[]} representation.
     * @return {@code byte[]} for given {@code integer}.
     */
    private static byte[] toByteArray(BigInteger integer) {

        byte[] result = integer.toByteArray();
        if (integer.bitLength() % 8 == 0 && integer.bitLength() / 8 != result.length) {
            // sign bit - leading 0
            result = Arrays.copyOfRange(result, 1, result.length);
        }

        return result;
    }
}
