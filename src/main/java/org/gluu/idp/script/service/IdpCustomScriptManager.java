package org.gluu.idp.script.service;

import org.gluu.idp.externalauth.openid.conf.IdpConfigurationFactory;
import org.gluu.idp.script.service.external.IdpExternalScriptService;
import org.gluu.service.custom.script.StandaloneCustomScriptManager;

/**
 * IDP Custom Script Manager
 * 
 * @author Yuriy Movchan
 * @version 0.1, 06/18/2020
 */
public class IdpCustomScriptManager extends StandaloneCustomScriptManager {

	private static final long serialVersionUID = 2727779937414218627L;

	private IdpExternalScriptService idpExternalScriptService;

	public IdpCustomScriptManager(final IdpConfigurationFactory configurationFactory) {
		super(configurationFactory.getPersistenceEntryManager(),
			  configurationFactory.getAppConfiguration().getScriptDn(),
			  configurationFactory.getBaseConfiguration().getString("pythonModulesDir"));
	}
	
	public void init() {
		// Create external script
		this.idpExternalScriptService = new IdpExternalScriptService();

		// Register required external scripts
		registerExternalScriptService(idpExternalScriptService);

		// Init script manager and load scripts
		super.init();
	}
	
	public IdpExternalScriptService getIdpExternalScriptService() {
		return idpExternalScriptService;
	}

}
