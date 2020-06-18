package org.gluu.idp.script.service;

import org.gluu.idp.externalauth.openid.conf.IdpConfigurationFactory;
import org.gluu.idp.script.service.external.IdpExternalScriptService;
import org.gluu.service.custom.script.CustomScriptManager;

/**
 * IDP Custom Script Manager
 * 
 * @author Yuriy Movchan
 * @version 0.1, 06/18/2020
 */
public class IdpCustomScriptManager {
	
	private CustomScriptManager customScriptManager;

	private static final long serialVersionUID = 2727779937414218627L;

	public IdpCustomScriptManager(final IdpConfigurationFactory configurationFactory) {
		// TODO Auto-generated constructor stub
	}
	
	public IdpExternalScriptService getIdpExternalScriptService() {
		// TODO Auto-generated constructor stub
		
		return null;
	}

}
