package pers.wjh.krb.client;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.HashMap;
import java.util.Map;

/**
 * KerberosLoginConfig
 *
 * @since 2020/11/8
 */
class KerberosLoginConfig extends Configuration {
    private final String keyTabLocation;
    private final String userPrincipal;
    private final Map<String, Object> loginOptions;

    /**
     *
     * @param keyTabLocation path of keyTab
     * @param userPrincipal principal
     * @param loginOptions other parameters
     */
    public KerberosLoginConfig(String keyTabLocation, String userPrincipal, Map<String, Object> loginOptions){
        super();
        this.keyTabLocation = keyTabLocation;
        this.userPrincipal = userPrincipal;
        this.loginOptions = loginOptions;
    }

    boolean containsText(CharSequence str) {
        int strLen = str.length();
        for (int i = 0; i < strLen; i++) {
            if (!Character.isWhitespace(str.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    boolean hasNoText(String str) {
        return (str == null || str.isEmpty() || !containsText(str));
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        Map<String, Object> options = new HashMap<>(16);
        if (hasNoText(keyTabLocation) || hasNoText(userPrincipal)) {
            options.put("useTicketCache", "true");
        } else {
            // keytab
            options.put("useKeyTab", "true");
            options.put("keyTab", this.keyTabLocation);
            options.put("principal", this.userPrincipal);
            options.put("storeKey", "true");
        }
        options.put("doNotPrompt", "true");
        options.put("isInitiator", "true");

        if (loginOptions != null) {
            options.putAll(loginOptions);
        }

        return new AppConfigurationEntry[] { new AppConfigurationEntry(
                "com.sun.security.auth.module.Krb5LoginModule",
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
    }
}
