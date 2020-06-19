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
public class IdpCustomScriptManager {

	private StandaloneCustomScriptManager standaloneCustomScriptManager;
	private IdpExternalScriptService idpExternalScriptService;

	public IdpCustomScriptManager(final IdpConfigurationFactory configurationFactory) {
		standaloneCustomScriptManager = new StandaloneCustomScriptManager(
				configurationFactory.getPersistenceEntryManager(),
				configurationFactory.getAppConfiguration().getScriptDn(),
				configurationFactory.getBaseConfiguration().getString("pythonModulesDir"));
	}
	
	public void init() {
		// Create external script
		this.idpExternalScriptService = new IdpExternalScriptService();

		// Register required external scripts
		standaloneCustomScriptManager.registerExternalScriptService(idpExternalScriptService);

		// Init script manager and load scripts
		standaloneCustomScriptManager.init();
	}
	
	public IdpExternalScriptService getIdpExternalScriptService() {
		return idpExternalScriptService;
	}

}
