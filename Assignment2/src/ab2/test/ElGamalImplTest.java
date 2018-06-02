package ab2.test;

import ab2.ElGamal;
import ab2.impl.AuerEberlHarden.ElGamalImpl;
import org.hamcrest.MatcherAssert;
import org.junit.Ignore;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.function.Supplier;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

/**
 * Test class for testing {@link ElGamalImpl}.
 */
public class ElGamalImplTest {

    @Test
    public void defaultKeysAreNull() {

        // given
        ElGamalImpl target = new ElGamalImpl();

        // then, the public key is null
        assertThat(target.getPublicKey(), is(nullValue()));
        // and then, the private key is null too
        assertThat(target.getPrivateKey(), is(nullValue()));
    }

    @Test
    public void afterInitializingKeysAreNoLongerNull() {

        // given
        ElGamalImpl target = new ElGamalImpl();

        // when the target gets initialized
        target.init(512);

        // then, the public key is null
        assertThat(target.getPublicKey(), is(notNullValue()));
        // and then, the private key is null too
        assertThat(target.getPrivateKey(), is(notNullValue()));
    }

    @Test
    public void initializingTwiceGivesNewKeys() {

        // given
        ElGamalImpl target = new ElGamalImpl();

        // when initializing first time
        target.init(512);

        // then store the keys and verify non-null
        ElGamal.PublicKey publicKeyOne = target.getPublicKey();
        ElGamal.PrivateKey privateKeyOne = target.getPrivateKey();
        assertThat(publicKeyOne, is(notNullValue()));
        assertThat(privateKeyOne, is(notNullValue()));

        // and when calling init a second time
        target.init(512);

        // then
        assertThat(target.getPublicKey(), is(notNullValue()));
        assertThat(target.getPublicKey(), is(not(sameInstance(publicKeyOne))));
        assertThat(target.getPrivateKey(), is(notNullValue()));
        assertThat(target.getPrivateKey(), is(not(sameInstance(privateKeyOne))));
    }

    @Test
    public void keysAreAsExpected() {

        // given
        ElGamalImpl target = new ElGamalImpl();


        for (int keySize = 128; keySize <= 1024; keySize *= 2) {

            // when initializing the target
            target.init(keySize);

            // then public and private key are initialized
            assertThat(target.getPublicKey(), is(notNullValue()));
            assertThat(target.getPublicKey().getP(), is(notNullValue()));
            assertThat(target.getPublicKey().getG(), is(notNullValue()));
            assertThat(target.getPublicKey().getE(), is(notNullValue()));

            assertThat(target.getPrivateKey(), is(notNullValue()));
            assertThat(target.getPrivateKey().getP(), is(notNullValue()));
            assertThat(target.getPrivateKey().getG(), is(notNullValue()));
            assertThat(target.getPrivateKey().getD(), is(notNullValue()));

            // then public/private key share the same p and g
            // in theory a check for same instance could be done as well
            assertThat(target.getPublicKey().getP(), is(equalTo(target.getPrivateKey().getP())));
            assertThat(target.getPublicKey().getG(), is(equalTo(target.getPrivateKey().getG())));

            // and p is a prime with bitLength == keySize
            assertThat(target.getPublicKey().getP().isProbablePrime(100), is(true));
            assertThat(target.getPublicKey().getP().bitLength(), is(equalTo(keySize)));
        }
    }

    @Test
    public void encryptAndDecryptEmptyMessage() {

        // given
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        // when encrypting and decrypting
        byte[] cipher = target.encrypt(new byte[0]);
        byte[] message = target.decrypt(cipher);

        // then
        assertThat(cipher.length, is(equalTo((2 * 1024) / 8)));
        assertThat(message, is(equalTo(new byte[0])));
    }

    @Test
    public void encryptAndDecryptShortMessage() {

        // given
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        // when encrypting and decrypting
        byte[] cipher = target.encrypt(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05});
        byte[] message = target.decrypt(cipher);

        // then
        MatcherAssert.assertThat(message, is(equalTo(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05})));
    }

    @Test
    public void encryptAndDecryptZerosOnlyWorks() {
        // given
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)0);
            byte[] cipher = target.encrypt(data);
            byte[] message = target.decrypt(cipher);

            // then
            MatcherAssert.assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void encryptAndDecryptOnesOnlyWorks() {
        // given
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)0xff);
            byte[] cipher = target.encrypt(data);
            byte[] message = target.decrypt(cipher);

            // then
            MatcherAssert.assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void encryptAndDecryptRandomMessagesWorks() {
        // given
        SecureRandom random = new SecureRandom();
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)random.nextInt(256));
            byte[] cipher = target.encrypt(data);
            byte[] message = target.decrypt(cipher);

            // then
            MatcherAssert.assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void signingEmptyMessageWorks() {
        // given
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        byte[] message = new byte[0];

        // when
        byte[] signature = target.sign(message);

        // then
        assertThat(target.verify(message, signature), is(true));
    }

    @Test
    public void signingMessagesContainingZerosOnlyWorks() {
        // given
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when signing
            byte[] message = generateMessage(i, () -> (byte)0);
            byte[] signature = target.sign(message);

            // then
            assertThat(target.verify(message, signature), is(true));
        }
    }

    @Test
    public void signingMessagesContainingOnesOnlyWorks() {
        // given
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when signing
            byte[] message = generateMessage(i, () -> (byte)0xff);
            byte[] signature = target.sign(message);

            // then
            assertThat(target.verify(message, signature), is(true));
        }
    }

    @Test
    public void signingMessagesContainingRandomBytesWorks() {
        // given
        SecureRandom random = new SecureRandom();
        ElGamalImpl target = new ElGamalImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when signing
            byte[] message = generateMessage(i, () -> (byte)random.nextInt(256));
            byte[] signature = target.sign(message);

            // then
            assertThat(target.verify(message, signature), is(true));
        }
    }

    @Test
    @Ignore("Integration test")
    public void theNeverEndingStoryTest() {

        // create target
        ElGamalImpl target = new ElGamalImpl();

        SecureRandom random = new SecureRandom();
        int[] keyLengths = { 512, 1024, 2048 };

        for (int keyLength : keyLengths) {

            // init target based on keyLength
            target.init(keyLength);

            // verify the modulus lengths
            assertThat(target.getPublicKey().getP().bitLength(), is(equalTo(keyLength)));
            assertThat(target.getPrivateKey().getP().bitLength(), is(equalTo(keyLength)));

            // verify same p and g for public & private key
            assertThat(target.getPublicKey().getP(), is(equalTo(target.getPrivateKey().getP())));
            assertThat(target.getPublicKey().getG(), is(equalTo(target.getPrivateKey().getG())));

            // repeat for a very long time
            int numRepetitions = 1000 * 1000;
            for (int i = 0; i < numRepetitions; i++) {

                // now generate a random message
                byte[] message = generateMessage(random.nextInt(10 * 1024), () -> (byte) random.nextInt(256));

                // encrypt message
                byte[] cipher = target.encrypt(message);

                // cipher must be at least twice as long as the appropriate message
                assertThat(cipher.length >= 2* message.length, is(true));

                // verify that decryption works
                assertThat(target.decrypt(cipher), is(equalTo(message)));

                // destroy one bit in the cipher
                int byteIndex = random.nextInt(cipher.length);
                int bitIndex = random.nextInt(8);
                byte mask = (byte) (0x01 << bitIndex);
                cipher[byteIndex] ^= mask;
                // ensure decryption no longer works
                assertThat(target.decrypt(cipher), is(not(equalTo(message))));

                // sign the original message
                byte[] signature = target.sign(message);

                // verify that the signature is correct
                assertThat(target.verify(message, signature), is(true));

                // destroy one bit in the signature
                byteIndex = random.nextInt(signature.length);
                bitIndex = random.nextInt(8);
                mask = (byte) (0x01 << bitIndex);
                signature[byteIndex] ^= mask;

                // ensure that the signature verification fails now
                assertThat(target.verify(message, signature), is(false));

                if (((i + 1) % 1000) == 0) {
                    System.out.println("Passed " + (i + 1) + "/" + numRepetitions + " tests (keyLength=" + keyLength + ").");
                }
            }
        }
    }

    private static byte[] generateMessage(int length, Supplier<Byte> contentSupplier) {

        byte[] message = new byte[length];
        for (int i = 0; i < message.length; i++) {
            message[i] = contentSupplier.get();
        }

        return message;
    }
}
