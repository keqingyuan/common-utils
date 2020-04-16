package cc.kebei.commons.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class SecurityProvider {

    private static java.security.Provider PROVIDER = new BouncyCastleProvider();

    public static java.security.Provider BCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(PROVIDER);
        }
        return Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
}
