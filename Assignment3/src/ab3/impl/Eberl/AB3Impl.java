package ab3.impl.Eberl;

import ab3.AB3;
import ab3.CertTools;
import ab3.PasswordTools;

/**
 * Default implementation for {@link AB3}
 *
 * @author Stefan Eberl
 */
public class AB3Impl implements AB3 {

    @Override
    public CertTools newCertToolsInstance() {
        return new CertToolsImpl();
    }

    @Override
    public PasswordTools newPasswordToolsInstance() {
        return new PasswordToolsImpl();
    }
}
