package org.gluu.idp.externalauth.openid.conf;

import org.gluu.oxauth.client.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IDP configuration factory
 * 
 * @author Yuriy Movchan
 * @version 0.1, 09/13/2018
 */
public final class IdpConfiguration extends Configuration<IdpAppConfiguration, IdpLdapAppConfiguration> {

	private final Logger logger = LoggerFactory.getLogger(IdpConfiguration.class);

	private static class ConfigurationSingleton {
		static IdpConfiguration INSTANCE = new IdpConfiguration();
	}

	public static IdpConfiguration instance() {
		return ConfigurationSingleton.INSTANCE;
	}

	@Override
	protected String getLdapConfigurationFileName() {
		return "oxidp-ldap.properties";
	}

	@Override
	protected Class<IdpLdapAppConfiguration> getAppConfigurationType() {
		return IdpLdapAppConfiguration.class;
	}

	@Override
	protected String getApplicationConfigurationPropertyName() {
		return "oxidp_ConfigurationEntryDN";
	}

}
