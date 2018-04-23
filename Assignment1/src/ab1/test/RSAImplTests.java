package ab1.test;

import ab1.impl.BauerEberlJensch.RSAImpl;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class RSAImplTests {

    @Test
    public void theDefaultPublicKeyIsNullIfRSAImplIsNotInitialized() {

        // given
        RSAImpl target = new RSAImpl();

        // then
        assertThat(target.getPublicKey(), is(nullValue()));
    }

    @Test
    public void theDefaultPrivateKeyIsNullIfRSAImplIsNotInitialized() {

        // given
        RSAImpl target = new RSAImpl();

        // then
        assertThat(target.getPrivateKey(), is(nullValue()));
    }

}
