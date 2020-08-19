package org.gluu.idp.consent.processor;

import javax.annotation.Nonnull;

import org.gluu.idp.consent.processor.PostProcessAttributesContext;
import org.gluu.idp.externalauth.openid.conf.IdpConfigurationFactory;
import org.gluu.idp.script.service.IdpCustomScriptManager;
import org.gluu.idp.script.service.external.IdpExternalScriptService;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.consent.flow.ar.impl.AbstractAttributeReleaseAction;
import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.utilities.java.support.logic.Constraint;

public class GluuReleaseAttributesPostProcessor extends AbstractAttributeReleaseAction {

	private final Logger LOG = LoggerFactory.getLogger(GluuReleaseAttributesPostProcessor.class);

	private IdpConfigurationFactory configurationFactory;
	private IdpCustomScriptManager customScriptManager;
	private IdpExternalScriptService externalScriptService;

    public GluuReleaseAttributesPostProcessor() {
    	
    	configurationFactory = IdpConfigurationFactory.instance(); 
    	customScriptManager = new IdpCustomScriptManager(configurationFactory, true);
     
    	LOG.debug("ReleaseAttributesPostProcessor: create");
        Constraint.isNotNull(configurationFactory, "Configuration factory cannot be null");
        Constraint.isNotNull(customScriptManager, "Custom script manager cannot be null");
 
        init();
    }

    private void init() {
    	// Call custom script manager init to make sure that it initialized
    	this.customScriptManager.init();
    	this.externalScriptService = this.customScriptManager.getIdpExternalScriptService();
	}

	/**
     * Performs this profile interceptor action. Default implementation does nothing.
     * 
     * @param profileRequestContext the current profile request context
     * @param interceptorContext the current profile interceptor context
     */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	protected void doExecute(@Nonnull ProfileRequestContext profileRequestContext, @Nonnull ProfileInterceptorContext interceptorContext) {
		// Execute default flow first
		LOG.info("Executing external IDP script");
		super.doExecute(profileRequestContext, interceptorContext);

		// Return if script(s) not exists or invalid
		if (!this.externalScriptService.isEnabled()) {
			LOG.trace("Using default release attributes post processor");
			return;
		}
		
		LOG.info("Executing external IDP script");
		PostProcessAttributesContext context = buildContext();
		boolean result = this.externalScriptService.executeExternalUpdateAttributesMethod(context);

		LOG.debug("Executed script method 'updateAttributes' with result {}", result);
	}

	private PostProcessAttributesContext buildContext() {
		AttributeContext attributeContext = getAttributeContext();

		PostProcessAttributesContext context = new PostProcessAttributesContext();
		context.setAttributeContext(attributeContext);
		context.setAttributeReleaseAction(this);

		return context;
	}

}