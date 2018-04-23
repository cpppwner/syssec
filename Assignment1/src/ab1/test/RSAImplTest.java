package ab1.test;

import ab1.RSA;
import ab1.impl.BauerEberlJensch.RSAImpl;
import org.junit.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
}
