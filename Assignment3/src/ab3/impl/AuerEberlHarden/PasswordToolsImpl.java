package ab3.impl.AuerEberlHarden;

import ab3.PasswordTools;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * Default implementation for password tools
 *
 * @author Thomas Auer
 * @author Stefan Eberl
 * @author Igor Harden
 */
public class PasswordToolsImpl implements PasswordTools {

    /**
     * Salt length in bytes.
     */
    private static final int SALT_LENGTH = 32;

    /**
     * The number of iterations for PBKDF2 when hashing password.
     *
     * <p>
     *     Note: just for information purposes - the WPA-2 uses 4096 iterations.
     * </p>
     */
    private static final int SALTED_HASH_PBKDF2_ITERATIONS = 10000;

    /**
     * Hash length, required for PBKDF2.
     *
     * <p>
     *     Since the algorithm uses HMAC-SHA1, the hash length is 20 bytes.
     * </p>
     */
    private static final int PBKDF2_HLEN = 20;

    /**
     * Block size of HMAC.
     *
     * <p>
     *     This 64 bytes for SHA-1
     * </p>
     */
    private static final int HMAC_BLOCK_SIZE = 64;

    /**
     * HMAC outer padded block.
     */
    private static final byte[] HMAC_OPAD_BLOCK = new byte[HMAC_BLOCK_SIZE];

    /**
     * Byte used to fill up the {@link #HMAC_OPAD_BLOCK}.
     */
    private static final byte HMAC_OPAD_BYTE = 0x5c;

    /**
     * HMAC inner padded block;
     */
    private static final byte[] HMAC_IPAD_BLOCK = new byte[HMAC_BLOCK_SIZE];

    /**
     * Byte used to fill up the {@link #HMAC_IPAD_BLOCK}.
     */
    private static final byte HMAC_IPAD_BYTE = 0x36;

    /**
     * The desired key length when hashing password.
     *
     * <p>
     *     Note: just for information purposes - the WPA-2 uses 256.
     * </p>
     */
    private static final int  SALTED_HASH_PBKDF2_KEY_LENGTH = 512;

    /**
     * Certainty required to meet the spec of probablePrime
     */
    private static final int DEFAULT_PRIME_CERTAINTY = 100;

    /**
     * BigInteger representing the number 2, required for Blum-Blum-Shub
     */
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /**
     * BigInteger representing the number 3, required for Blum-Blum-Shub
     */
    private static final BigInteger THREE = BigInteger.valueOf(3);

    /**
     * BigInteger representing the number 3, required for Blum-Blum-Shub
     */
    private static final BigInteger FOUR = BigInteger.valueOf(4);

    static {
        // fill up HMAC_OPAD_BLOCK
        for (int i = 0; i < HMAC_OPAD_BLOCK.length; i++) {
            HMAC_OPAD_BLOCK[i] = HMAC_OPAD_BYTE;
        }
        // fill up HMAC_IPAD_BLOCK
        for (int i = 0; i < HMAC_IPAD_BLOCK.length; i++) {
            HMAC_IPAD_BLOCK[i] = HMAC_IPAD_BYTE;
        }
    }

    @Override
    public SaltedHash createSaltedHash(String password) {
        // generate a random salt
        byte[] salt = createSalt();
        // extract password bytes, using UTF-8 encoding
        byte[] passwordBytes = getPasswordBytes(password);

        // hash password + salt using default PBKDF2 parameters
        byte[] hash = PBKDF2(passwordBytes, salt, SALTED_HASH_PBKDF2_ITERATIONS, SALTED_HASH_PBKDF2_KEY_LENGTH);

        // return the computed hash + salt
        return new SaltedHash(hash, salt);
    }

    /**
     * Create random salt.
     *
     * <p>
     *     The random salt has a length of {@link #SALT_LENGTH} bytes.
     * </p>
     *
     * @return Randomly created salt.
     */
    private static byte[] createSalt() {

        byte[] salt = new byte[PasswordToolsImpl.SALT_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        return salt;
    }

    @Override
    public boolean checkSaltedHash(String password, SaltedHash hash) {
        // extract password bytes, using UTF-8 encoding
        byte[] passwordBytes = getPasswordBytes(password);
        // hash again, using the provided salt
        byte[] obtainedHash = PBKDF2(passwordBytes, hash.getSalt(), SALTED_HASH_PBKDF2_ITERATIONS, SALTED_HASH_PBKDF2_KEY_LENGTH);

        // compare the computed hash with given hash
        // if they are equal, everything is fine, otherwise password or hash are wrong
        return Arrays.equals(obtainedHash, hash.getHash());
    }

    /**
     * Get password bytes.
     *
     * <p>
     *     The charset used for byte conversion is UTF-8.
     * </p>
     *
     * @param password The string password for which to get the bytes.
     * @return Byte representation of password.
     */
    private static byte[] getPasswordBytes(String password) {

        if (password == null) {
            return null;
        }
        return password.getBytes(Charset.forName("UTF-8"));
    }

    @Override
    public byte[] PBKDF2(byte[] password, byte[] salt, int iterations, int dkLen) {

        // validate input parameters
        if (iterations < 1) {
            // iteration count must be a positive integer
            return null;
        }
        if (dkLen < 1) {
            // dkLen must be a positive integer
            return null;
        }
        if (password == null) {
            return null;
        }
        if (salt == null) {
            return null;
        }


        // step 1: If dkLen > (2^32 - 1) * hLen
        // since dkLen is int and thus cannot be greater than 2^32 - 1, this check is superfluous

        // l = CEIL (dkLen / hLen)
        int l = (dkLen / PBKDF2_HLEN) + ((dkLen % PBKDF2_HLEN == 0) ? 0 : 1);

        //  r = dkLen - (l - 1) * hLen
        int  r = dkLen - (l - 1) * PBKDF2_HLEN;

        byte[] T = r == 0 ? new byte[l * PBKDF2_HLEN] : new byte[(l - 1) * PBKDF2_HLEN + r];
        for (int i = 0; i < l; i++)
        {
            // apply function F
            byte[] tmp = F(password, salt, iterations, i + 1);
            // copy result into T
            int length = (i == l - 1) ? r : PBKDF2_HLEN;
            System.arraycopy(tmp, 0, T, i * PBKDF2_HLEN, length);
        }

        // extract derived key and return it
        return T;
    }

    /**
     * Function applied to each input block by {@link #PBKDF2(byte[], byte[], int, int)}.
     *
     * <p>
     *     This function is implemented as described in <a href="https://tools.ietf.org/html/rfc2898#page-9">https://tools.ietf.org/html/rfc2898#page-9</a>
     * </p>
     *
     * @param password Password
     * @param salt Salt
     * @param iterations The number of iterations
     * @param blockIndex The block index, starting with 1.
     * @return The resulting byte array.
     */
    private static byte[] F(byte[] password, byte[] salt, int iterations, int blockIndex) {

        // U_1 = PRF (P, S || INT (i)) ,
        // U_2 = PRF (P, U_1) ,
        // ...
        // U_c = PRF (P, U_{c-1}) .

        // resulting byte array
        byte[] result = new byte[PBKDF2_HLEN];
        
        // let's start with U_0, which is S || INT(i) (concatenate salt with integer repr of i).
        // Note: salt might still be null, in this case it's just INT(i)
        byte[] U_i = concatenate(salt, INT(blockIndex));

        for (int i = 0; i < iterations; i++) {
            U_i = hmacSHA1(password, U_i);
            xor(result, U_i);
        }

        return result;
    }

    /**
     * Concatenate two byte arrays into one single byte array.
     *
     * <p>
     *     There are three possible cases.
     *     <ol>
     *         <li>prefix is null -> suffix is returned</li>
     *         <li>suffix is null -> prefix is returned</li>
     *         <li>prefix and suffix are not null -> concatenation is returned.</li>
     *     </ol>
     * </p>
     *
     * @param prefix First byte array in concatenation.
     * @param suffix Second byte array in concatentation.
     * @return Concatenated byte array.
     */
    private static byte[] concatenate(byte[] prefix, byte[] suffix) {

        if (prefix == null && suffix == null) {
            throw new IllegalArgumentException("prefix and suffix cannot be both null.");
        }

        if (prefix == null) {
            return suffix;
        } else if (suffix == null) {
            return prefix;
        }

        // both arrays are not null - do real concatenation
        byte[] result = new byte[prefix.length + suffix.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(suffix, 0, result, prefix.length, suffix.length);

        return result;
    }

    /**
     * Convert given integer i into byte array in big-endian order.
     *
     * @param i The integer to convert into byte[] representation.
     * @return Byte array representation (big-endian) of given integer i.
     */
    private static byte[] INT(int i) {

        byte[] result = new byte[Integer.BYTES];

        result[0] = (byte) (i >> 24);
        result[1] = (byte) (i >> 16);
        result[2] = (byte) (i >> 8);
        result[3] = (byte) (i);

        return result;
    }

    /**
     * Apply HMAC-SHA1 pseudo-random function on given password and ui.
     *
     * @param key HMAC's secret key (aka password).
     * @param text HMAC's text (aka salt).
     * @return Result of PRF.
     */
    private static byte[] hmacSHA1(byte[] key, byte[] text) {

        // Keys longer than blockSize are shortened by hashing them
        if (key.length > HMAC_BLOCK_SIZE) {
            // key now becomes 20 bytes long (SHA-1 output size).
            key = sha1(key);
        }
        // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
        if (key.length < HMAC_BLOCK_SIZE) {
            // copyOf will pad with 0
            key = Arrays.copyOf(key, HMAC_BLOCK_SIZE);
        }

        // generate outer key pad
        byte[] outerKeyPad = Arrays.copyOf(HMAC_OPAD_BLOCK, HMAC_OPAD_BLOCK.length);
        xor(outerKeyPad, key);

        // generate inner key pad
        byte[] innerKeyPad = Arrays.copyOf(HMAC_IPAD_BLOCK, HMAC_IPAD_BLOCK.length);
        xor(innerKeyPad, key);

        return sha1(concatenate(outerKeyPad, sha1(concatenate(innerKeyPad, text))));
    }

    /**
     * Compute SHA-1 hash over given data.
     *
     * @param data The data on which the SHA-1 hashing function is applied.
     * @return SHA-1 hashed data.
     */
    private static byte[] sha1(byte[] data) {

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        return messageDigest.digest(data);
    }

    /**
     * Compute byte-wise xor.
     *
     * @param dest The destination byte array.
     * @param src The source byte array.
     */
    private static void xor(byte[] dest, byte[] src) {

        for (int i = 0; i < dest.length; i++) {
            dest[i] ^= src[i];
        }
    }

    @Override
    public byte[] generateRandomBytes(int len, int secLen) {

        // initialize Blum Blum Shub RNG
        SecureRandom random = new SecureRandom();
        BigInteger n = generateBlumInteger(secLen, random);
        BigInteger seed = generateSeed(n, random);

        return generateRandomBytes(len, n, seed);
    }

    /**
     * Generate sequence of random bytes using Blum Blum Shub
     *
     * @param numBytes The number of bytes.
     * @param n The modul.
     * @param seed Initial seed.
     * @return Random generated byte.
     */
    private static byte[] generateRandomBytes(int numBytes, BigInteger n, BigInteger seed) {

        byte[] result = new byte[numBytes];
        BigInteger state = seed.mod(n);

        for (int byteIndex = 0; byteIndex < result.length; byteIndex++) {

            int random = 0;
            for (int bitIndex = 0; bitIndex < Byte.SIZE; bitIndex++) {
                state = state.modPow(TWO, n);
                random <<= 1;
                random |= state.testBit(0) ? 1 : 0;
            }

            result[byteIndex] = (byte)random;
        }

        return result;
    }

    /**
     * Generate seed for the Blum Blum Shub RNG for given Blum number.
     *
     * <p>
     *     The seed is a number which where gcd(n, seed) == 1
     * </p>
     *
     * @param n The Blum integer for which tso generate a seed.
     * @param random Secure PRNG for seed generation.
     * @return The generated seed.
     */
    private static BigInteger generateSeed(BigInteger n, SecureRandom random) {

        BigInteger seed;
        do {
            seed = new BigInteger(1, random.generateSeed(n.bitCount() / 8));
        } while (!n.gcd(seed).equals(BigInteger.ONE));

        return seed;
    }

    /**
     * Generate a Blum integer.
     *
     * <p>
     *     A Blum integer is the product of two primes p and q (result = p * q),
     *     where p and q are both congruent to 3 mod 4.
     * </p>
     *
     * @param secLen The length of the Blum integer.
     * @param random The PRNG used for prime generation.
     * @return The generated Blum integer.
     */
    private static BigInteger generateBlumInteger(int secLen, Random random) {

        BigInteger n;
        do {
            BigInteger p = generateBlumIntegerFactor(secLen / 2, random);
            BigInteger q;
            do {
                q = generateBlumIntegerFactor(secLen / 2, random);
            } while (p.equals(q));

            n = p.multiply(q);
        } while (n.bitLength() != secLen);

        return n;
    }

    /**
     * Generate a Blum integer factor.
     *
     * <p>
     *     The result is a random prime with bit length numBits.
     * </p>
     *
     * @param numBits The number of bits for the prime number.
     * @param random The PRNG for prime generation.
     * @return A prime number which is a factor for the Blum integer generation.
     */
    private static BigInteger generateBlumIntegerFactor(int numBits, Random random) {

        BigInteger result;
        do {
            result = new BigInteger(numBits, DEFAULT_PRIME_CERTAINTY, random);
        } while (result.bitLength() != numBits || !result.mod(FOUR).equals(THREE));

        return result;
    }
}
