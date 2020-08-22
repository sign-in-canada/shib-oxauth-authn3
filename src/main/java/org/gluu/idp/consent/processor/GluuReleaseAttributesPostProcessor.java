package org.gluu.idp.consent.processor;

import java.util.function.Function;

import javax.annotation.Nonnull;

import org.gluu.idp.externalauth.openid.conf.IdpConfigurationFactory;
import org.gluu.idp.script.service.IdpCustomScriptManager;
import org.gluu.idp.script.service.external.IdpExternalScriptService;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.logic.Constraint;

public class GluuReleaseAttributesPostProcessor extends AbstractProfileAction {

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
	 * Performs this profile interceptor action. Default implementation does
	 * nothing.
	 * 
	 * @param profileRequestContext the current profile request context
	 * @param interceptorContext    the current profile interceptor context
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
		// Execute default flow first
		LOG.info("Executing external IDP script");
		super.doExecute(profileRequestContext);

		PostProcessAttributesContext context = buildContext(profileRequestContext);

		AttributeContext attributeContext = context.getAttributeContext();
		for (String attr : attributeContext.getIdPAttributes().keySet()) {
			LOG.info("------------------------attr: {}", attr);
		}

		// Return if script(s) not exists or invalid
		if (!this.externalScriptService.isEnabled()) {
			LOG.info("Using default release attributes post processor");
			return;
		}

		boolean result = this.externalScriptService.executeExternalUpdateAttributesMethod(context);

		LOG.debug("Executed script method 'updateAttributes' with result {}", result);
	}

	private PostProcessAttributesContext buildContext(final ProfileRequestContext profileRequestContext) {

		Function<ProfileRequestContext, AttributeContext> attributeContextLookupStrategy = null;
		attributeContextLookupStrategy = new ChildContextLookup<>(AttributeContext.class).compose(new ChildContextLookup<>(RelyingPartyContext.class));

		AttributeContext attributeContext = attributeContextLookupStrategy.apply(profileRequestContext);

		PostProcessAttributesContext context = new PostProcessAttributesContext();
		context.setAttributeContext(attributeContext);
		context.setAttributeReleaseAction(this);

		return context;
	}

}