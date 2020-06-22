package org.gluu.idp.consent.processor;

import java.io.Serializable;

import net.shibboleth.idp.attribute.context.AttributeContext;

/**
 * Release attributes context
 *
 * @author Yuriy Movchan
 * @version 0.1, 06/22/2020
 */
public class ReleaseAttributesContext implements Serializable {

	private static final long serialVersionUID = 1822377169827670256L;

	private AttributeContext attributeContext;
	private ReleaseAttributesPostProcessor releaseAttributesPostProcessor;

	public void setAttributeContext(AttributeContext attributeContext) {
		this.attributeContext = attributeContext;
	}

	public AttributeContext getAttributeContext() {
		return attributeContext;
	}

	public void setAttributeReleaseAction(ReleaseAttributesPostProcessor releaseAttributesPostProcessor) {
		this.releaseAttributesPostProcessor = releaseAttributesPostProcessor;
	}

	public ReleaseAttributesPostProcessor getReleaseAttributesPostProcessor() {
		return releaseAttributesPostProcessor;
	}

	public void setReleaseAttributesPostProcessor(ReleaseAttributesPostProcessor releaseAttributesPostProcessor) {
		this.releaseAttributesPostProcessor = releaseAttributesPostProcessor;
	}

}
