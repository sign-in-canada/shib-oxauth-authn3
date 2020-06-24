package org.gluu.idp.externalauth;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.gluu.oxauth.client.auth.user.UserProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

/**
 * Simple translation of the principal name from the oxAuth user profile to the string value used by Shib
 *
 * @author Yuriy Movchan
 * @version 0.1, 09/13/2018
 */
public class AuthenticatedNameTranslator implements OxAuthToShibTranslator {
    private final Logger logger = LoggerFactory.getLogger(AuthenticatedNameTranslator.class);

    @Override
    public void doTranslation(HttpServletRequest request, HttpServletResponse response, UserProfile userProfile, String authenticationKey)
            throws Exception {
        if ((userProfile == null) || (userProfile.getId() == null)) {
            logger.error("No valid user profile or principal could be found to translate");
            return;
        }

        logger.debug("User profile found: '{}'", userProfile);

        // Pass authenticated principal back to IdP to finish its part of authentication request processing
        final Collection<IdPAttributePrincipal> profileAttributes = produceIdpAttributePrincipal(userProfile.getAttributes());

        if (!profileAttributes.isEmpty()) {
            logger.debug("Found attributes from oxAuth. Processing...");
            final Set<Principal> principals = new HashSet<>();

            principals.addAll(profileAttributes);
            principals.add(new UsernamePrincipal(userProfile.getId()));

            request.setAttribute(ExternalAuthentication.SUBJECT_KEY, new Subject(false, principals,
                Collections.emptySet(), Collections.emptySet()));
            logger.info("Created an IdP subject instance with principals containing attributes for {} ", userProfile.getId());

        } else {
            logger.debug("No attributes released from oxAuth. Creating an IdP principal for {}", userProfile.getId());
            request.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, userProfile.getId());
        }
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(final Object that) {
        return EqualsBuilder.reflectionEquals(this, that);
    }

    public Collection<IdPAttributePrincipal> produceIdpAttributePrincipal(final Map<String, Object> openidAttributes) {
        final Set<IdPAttributePrincipal> principals = new HashSet<>();
        for (final Map.Entry<String, Object> entry : openidAttributes.entrySet()) {
            final IdPAttribute attr = new IdPAttribute(entry.getKey());

            final List<IdPAttributeValue> attributeValues = new ArrayList<>();
            if (entry.getValue() instanceof Collection) {
                for (final Object value : (Collection) entry.getValue()) {
                    attributeValues.add(new StringAttributeValue(value.toString()));
                }
            } else {
                attributeValues.add(new StringAttributeValue(entry.getValue().toString()));
            }
            if (!attributeValues.isEmpty()) {
                attr.setValues(attributeValues);
                logger.debug("Added attribute {} with values {}", entry.getKey(), entry.getValue());
                principals.add(new IdPAttributePrincipal(attr));
            } else {
                logger.warn("Skipped attribute {} since it contains no values", entry.getKey());
            }
        }

        return principals;
    }

}
