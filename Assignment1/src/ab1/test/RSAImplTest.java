package ab1.test;

import ab1.RSA;
import ab1.impl.BauerEberlJensch.RSAImpl;
import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Supplier;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

public class RSAImplTest {

    @Test
    public void defaultPublicKeyIsNull() {
        // given
        RSAImpl target = new RSAImpl();

        // then
        assertThat(target.getPublicKey(), is(nullValue()));
    }

    @Test
    public void defaultPrivateKeyIsNull() {
        // given
        RSAImpl target = new RSAImpl();

        // then
        assertThat(target.getPrivateKey(), is(nullValue()));
    }

    @Test
    public void afterRsaIsInitializedPublicKeyIsNoLongerNull() {
        // given
        RSAImpl target = new RSAImpl();

        // when
        target.init(1024);

        // then
        assertThat(target.getPublicKey(), is(notNullValue()));
    }

    @Test
    public void afterRsaIsInitializedPrivateKeyIsNoLongerNull() {
        // given
        RSAImpl target = new RSAImpl();

        // when
        target.init(1024);

        // then
        assertThat(target.getPrivateKey(), is(notNullValue()));
    }

    @Test
    public void callingInitializeASecondTimeGivesDifferentPublicKey() {
        // given
        RSAImpl target = new RSAImpl();

        // when initializing first time
        target.init(1024);
        RSA.PublicKey firstKey = target.getPublicKey();

        // when initializing second time
        target.init(1024);
        RSA.PublicKey secondKey = target.getPublicKey();

        // then
        assertThat(secondKey, is(not(sameInstance(firstKey))));
    }

    @Test
    public void callingInitializeASecondTimeGivesDifferentPrivateKey() {
        // given
        RSAImpl target = new RSAImpl();

        // when initializing first time
        target.init(1024);
        RSA.PrivateKey firstKey = target.getPrivateKey();

        // when initializing second time
        target.init(1024);
        RSA.PrivateKey secondKey = target.getPrivateKey();

        // then
        assertThat(secondKey, is(not(sameInstance(firstKey))));
    }

    @Test
    public void modulusSizeIsSameAsGivenKeySizeWithinOneBit() {

        // given
        RSAImpl target = new RSAImpl();

        for (int size = 128; size <= 4096; size *= 2) {

            // when
            target.init(size);

            // then
            assertThat(target.getPublicKey().getN(), is(equalTo(target.getPrivateKey().getN())));
            BigInteger n = target.getPublicKey().getN();
            assertThat(n.bitLength(), is(equalTo(size)));
        }
    }

    @Test
    public void encryptAndDecryptEmptyMessageWithOAEPFalse() {

        // given
        RSAImpl target = new RSAImpl();
        target.init(1024);

        // when encrypting and decrypting
        byte[] cipher = target.encrypt(new byte[0], false);
        byte[] message = target.decrypt(cipher);

        // then
        assertThat(message, is(equalTo(new byte[0])));
    }

    @Test
    public void encryptAndDecryptShortMessageWithOAEPFalse() {

        // given
        RSAImpl target = new RSAImpl();
        target.init(1024);

        // when encrypting and decrypting
        byte[] cipher = target.encrypt(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}, false);
        byte[] message = target.decrypt(cipher);

        // then
        assertThat(message, is(equalTo(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05})));
    }

    @Test
    public void encryptAndDecryptEmptyMessageWithOAEPTrue() {

        // given
        RSAImpl target = new RSAImpl();
        target.init(1024);

        // when encrypting and decrypting
        byte[] cipher = target.encrypt(new byte[0], true);
        byte[] message = target.decrypt(cipher);

        // then
        assertThat(message, is(equalTo(new byte[0])));
    }

    @Test
    public void encryptAndDecryptShortMessageWithOAEPTrue() {

        // given
        RSAImpl target = new RSAImpl();
        target.init(1024);

        // when encrypting and decrypting
        byte[] cipher = target.encrypt(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}, true);
        byte[] message = target.decrypt(cipher);

        // then
        assertThat(message, is(equalTo(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05})));
    }

    @Test
    public void encryptAndDecryptZerosOnlyWorksWithOAEPFalse() {
        // given
        RSAImpl target = new RSAImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)0);
            byte[] cipher = target.encrypt(data, false);
            byte[] message = target.decrypt(cipher);

            // then
            assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void encryptAndDecryptZerosOnlyWorksWithOAEPTrue() {
        // given
        RSAImpl target = new RSAImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)0);
            byte[] cipher = target.encrypt(data, true);
            byte[] message = target.decrypt(cipher);

            // then
            assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void encryptAndDecryptOnesOnlyWorksWithOAEPFalse() {
        // given
        RSAImpl target = new RSAImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)0xff);
            byte[] cipher = target.encrypt(data, false);
            byte[] message = target.decrypt(cipher);

            // then
            assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void encryptAndDecryptOnesOnlyWorksWithOAEPTrue() {
        // given
        RSAImpl target = new RSAImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)0xff);
            byte[] cipher = target.encrypt(data, true);
            byte[] message = target.decrypt(cipher);

            // then
            assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void encryptAndDecryptRandomMessagesWorksWithOAEPFalse() {
        // given
        SecureRandom random = new SecureRandom();
        RSAImpl target = new RSAImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)random.nextInt(256));
            byte[] cipher = target.encrypt(data, false);
            byte[] message = target.decrypt(cipher);

            if (!Arrays.equals(data, message)) {
                cipher = target.encrypt(data, false);
                message = target.decrypt(cipher);
            }

            // then
            assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void encryptAndDecryptRandomMessagesWorksWithOAEPTrue() {
        // given
        SecureRandom random = new SecureRandom();
        RSAImpl target = new RSAImpl();
        target.init(1024);

        for (int i = 1; i < 4 * 1024; i++) {
            // when encrypting and decrypting
            byte[] data = generateMessage(i, () -> (byte)random.nextInt(256));
            byte[] cipher = target.encrypt(data, true);
            byte[] message = target.decrypt(cipher);

            // then
            assertThat(message, is(equalTo(data)));
        }
    }

    @Test
    public void signingEmptyMessageWorks() {
        // given
        RSAImpl target = new RSAImpl();
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
        RSAImpl target = new RSAImpl();
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
        RSAImpl target = new RSAImpl();
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
        RSAImpl target = new RSAImpl();
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
    //@Ignore("Integration test")
    public void theNeverEndingStoryTest() {

        SecureRandom random = new SecureRandom();
        int[] keyLengths = { 512, 1024, 2048, 4096 };

        // repeat for a very long time
        for (int i = 0; i < 1024 * 1024; i++) {

            // generate a random keyLength
            int keyLength = keyLengths[random.nextInt(keyLengths.length)];

            // create and initialize target
            RSAImpl target = new RSAImpl();
            target.init(keyLength);

            // verify the modulus lengths
            assertThat(target.getPublicKey().getN().bitLength(), is(equalTo(keyLength)));
            assertThat(target.getPrivateKey().getN().bitLength(), is(equalTo(keyLength)));

            // now generate a random message
            byte[] message = generateMessage(random.nextInt(100 * 1024), () -> (byte)random.nextInt(256));

            // encrypt message
            byte[] cipherWithOAEP = target.encrypt(message, true);
            byte[] cipherWithoutOAEP = target.encrypt(message, false);

            // verify that messages are not the same
            assertThat(cipherWithOAEP, is(not(equalTo(cipherWithoutOAEP))));

            // verify that decryption works
            assertThat(target.decrypt(cipherWithOAEP), is(equalTo(message)));
            assertThat(target.decrypt(cipherWithoutOAEP), is(equalTo(message)));

            // destroy one bit in the OAEP padded cipher
            // (do not destroy first byte, since this contains the padding scheme)
            int byteIndex = random.nextInt(cipherWithOAEP.length - 1) + 1;
            int bitIndex = random.nextInt(8);
            byte mask = (byte)(0x01 << bitIndex);
            cipherWithOAEP[byteIndex] ^= mask;
            // ensure decryption no longer works
            assertThat(target.decrypt(cipherWithOAEP), is(not(equalTo(message))));

            // destroy one bit in the non-OAEP padded cipher
            // (do not destroy first byte, since this contains the padding scheme)
            byteIndex = random.nextInt(cipherWithoutOAEP.length - 1) + 1;
            bitIndex = random.nextInt(8);
            mask = (byte)(0x01 << bitIndex);
            cipherWithoutOAEP[byteIndex] ^= mask;
            // ensure decryption no longer works
            assertThat(target.decrypt(cipherWithoutOAEP), is(not(equalTo(message))));

            // sign the original message
            byte[] signature = target.sign(message);

            // verify that the signature is correct
            assertThat(target.verify(message, signature), is(true));

            // destroy one bit in the signature
            byteIndex = random.nextInt(signature.length);
            bitIndex = random.nextInt(8);
            mask = (byte)(0x01 << bitIndex);
            signature[byteIndex] ^= mask;

            // ensure that the signature verification fails now
            assertThat(target.verify(message, signature), is(false));
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
