package org.gluu.idp.consent.processor;

import javax.annotation.Nonnull;

import org.gluu.idp.externalauth.openid.conf.IdpConfigurationFactory;
import org.gluu.idp.script.service.IdpCustomScriptManager;
import org.gluu.idp.script.service.external.IdpExternalScriptService;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.consent.flow.ar.impl.ReleaseAttributes;
import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Release attributes post processor
 *
 * @author Yuriy Movchan
 * @version 0.1, 06/22/2020
 */
public class GluuReleaseAttributesPostProcessor extends ReleaseAttributes {

	private final Logger LOG = LoggerFactory.getLogger(GluuReleaseAttributesPostProcessor.class);

	private IdpConfigurationFactory configurationFactory;
	private IdpCustomScriptManager customScriptManager;
	private IdpExternalScriptService externalScriptService;

    public GluuReleaseAttributesPostProcessor(final IdpConfigurationFactory configurationFactory, final IdpCustomScriptManager customScriptManager) {
    	LOG.debug("ReleaseAttributesPostProcessor: create");
        Constraint.isNotNull(configurationFactory, "Configuration factory cannot be null");
        this.configurationFactory = configurationFactory;

        Constraint.isNotNull(customScriptManager, "Custom script manager cannot be null");
        this.customScriptManager = customScriptManager;

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
		super.doExecute(profileRequestContext, interceptorContext);

		// Return if script(s) not exists or invalid
		if (!this.externalScriptService.isEnabled()) {
			LOG.trace("Using default release attributes post processor");
			return;
		}
		
		LOG.trace("Executing external IDP script");
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