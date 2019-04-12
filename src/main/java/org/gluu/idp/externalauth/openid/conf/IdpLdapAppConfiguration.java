package org.gluu.idp.externalauth.openid.conf;

import org.gluu.oxauth.client.conf.LdapAppConfiguration;
import org.gluu.persist.annotation.AttributeName;
import org.gluu.persist.annotation.JsonObject;

/**
 * Ldap application configuration model
 * 
 * @author Yuriy Movchan
 * @version 0.1, 09/13/2018
 */
public class IdpLdapAppConfiguration extends LdapAppConfiguration {

    private static final long serialVersionUID = -7301311833970330177L;

    @JsonObject
    @AttributeName(name = "oxConfApplication")
    private IdpAppConfiguration application;

    @Override
    public IdpAppConfiguration getApplication() {
        return application;
    }

    public void setApplication(IdpAppConfiguration application) {
        this.application = application;
    }

}
