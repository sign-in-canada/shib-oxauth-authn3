package org.gluu.idp.externalauth;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.commons.lang.StringUtils;
import org.gluu.idp.externalauth.openid.client.IdpAuthClient;
import org.gluu.oxauth.client.auth.principal.OpenIdCredentials;
import org.gluu.oxauth.client.auth.user.UserProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.web.context.WebApplicationContext;
import org.xdi.context.J2EContext;
import org.xdi.context.WebContext;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;

/**
 * A Servlet that validates the oxAuth code and then pushes the authenticated
 * principal name into the correct location before handing back control to Shib
 *
 * @author Yuriy Movchan
 * @version 0.1, 09/13/2018
 */
@WebServlet(name = "ShibOxAuthAuthServlet", urlPatterns = { "/Authn/oxAuth/*" })
public class ShibOxAuthAuthServlet extends HttpServlet {

    private static final long serialVersionUID = -4864851392327422662L;

    private final Logger logger = LoggerFactory.getLogger(ShibOxAuthAuthServlet.class);

    private final String OXAUTH_PARAM_ENTITY_ID = "entityId";
    private final String OXAUTH_PARAM_CONV_ID = "convId";

    @Autowired
    @Qualifier("idpOxAuthClient")
    private IdpAuthClient idpAuthClient;

    private final Set<OxAuthToShibTranslator> translators = new HashSet<OxAuthToShibTranslator>();

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);

        this.idpAuthClient = new IdpAuthClient();

        final ApplicationContext ac = (ApplicationContext) config.getServletContext()
                .getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);

        buildTranslators(ac.getEnvironment());
    }

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException {
        try {
            // Web context
            final WebContext webContext = new J2EContext(request, response);

            // Start external authentication
            final HttpServletRequestWrapper wrappedRequest = new HttpServletRequestWrapper(request) {

                @Override
                public String getParameter(String name) {
                    if (ExternalAuthentication.CONVERSATION_KEY.equals(name)) {
                        String convId = super.getHeader(OXAUTH_PARAM_CONV_ID);
                        if (convId != null) {
                            return convId;
                        }
                    }

                    return super.getParameter(name);
                }
                
            };
            final String authenticationKey = ExternalAuthentication.startExternalAuthentication(wrappedRequest);
            

            // Get external authentication properties
            final boolean force = Boolean.parseBoolean(request.getAttribute(ExternalAuthentication.FORCE_AUTHN_PARAM).toString());

            // It's an authentication
            if (!idpAuthClient.isAuthorizationResponse(webContext)) {
                logger.debug("Initiating oxAuth login redirect");
                startLoginRequest(request, response, force);
                return;
            }

            logger.info("Procession authorization response");

            // Check if oxAuth request state is correct
            if (!idpAuthClient.isValidRequestState(webContext)) {
                logger.error("The state in session and in request are not equals");

                // Re-init login page
                startLoginRequest(request, response, force);
                return;
            }

            processAuthorizationResponse(request, response, authenticationKey);

        } catch (final ExternalAuthenticationException ex) {
            logger.warn("Error processing oxAuth authentication request", ex);
            loadErrorPage(request, response);

        } catch (final Exception ex) {
            logger.error("Something unexpected happened", ex);
            request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.AUTHN_EXCEPTION);
        }
    }

    private void processAuthorizationResponse(final HttpServletRequest request, final HttpServletResponse response, final String authenticationKey)
            throws ExternalAuthenticationException, IOException {
        try {
            // Web context
            final WebContext webContext = new J2EContext(request, response);

            final OpenIdCredentials openIdCredentials = idpAuthClient.getCredentials(webContext);
            logger.debug("Client name : '{}'", openIdCredentials.getClientName());

            final UserProfile userProfile = idpAuthClient.getUserProfile(openIdCredentials, webContext);
            logger.debug("User profile : {}", userProfile);

            if (userProfile == null) {
                logger.error("Token validation failed, returning InvalidToken");
                request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "InvalidToken");
            } else {
                for (final OxAuthToShibTranslator translator : translators) {
                    translator.doTranslation(request, response, userProfile, authenticationKey);
                }
            }
        } catch (final Exception ex) {
            logger.error("Token validation failed, returning InvalidToken", ex);
            request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "InvalidToken");
        } finally {
            ExternalAuthentication.finishExternalAuthentication(authenticationKey, request, response);
        }
    }

    protected void startLoginRequest(final HttpServletRequest request, final HttpServletResponse response, final Boolean force) {
        try {
            // Web context
            final WebContext webContext = new J2EContext(request, response);

            final Map<String, String> customResponseHeaders = new HashMap<String, String>();
            final String convId = request.getParameter(ExternalAuthentication.CONVERSATION_KEY);
            customResponseHeaders.put(OXAUTH_PARAM_CONV_ID, convId);
            
            final Map<String, String> customParameters = new HashMap<String, String>();
            final String relayingPartyId = request.getAttribute(ExternalAuthentication.RELYING_PARTY_PARAM).toString();
            customParameters.put(OXAUTH_PARAM_ENTITY_ID, relayingPartyId);

            final String loginUrl = idpAuthClient.getRedirectionUrl(webContext, customResponseHeaders, customParameters);
            logger.debug("Generated redirection Url", loginUrl);

            logger.debug("loginUrl: {}", loginUrl);
            response.sendRedirect(loginUrl);
        } catch (final IOException ex) {
            logger.error("Unable to redirect to oxAuth from ShibOxAuth", ex);
        }
    }

    /**
     * Attempt to build the set of translators from the fully qualified class names
     * set in the properties. If nothing has been set then default to the
     * AuthenticatedNameTranslator only.
     */
    private void buildTranslators(final Environment environment) {
        translators.add(new AuthenticatedNameTranslator());

        final String oxAuthToShibTranslators = StringUtils.defaultString(environment.getProperty("shib.oxauth.oxAuthToShibTranslator", ""));
        for (final String classname : StringUtils.split(oxAuthToShibTranslators, ';')) {
            try {
                logger.debug("Loading translator class {}", classname);
                final Class<?> c = Class.forName(classname);
                final OxAuthToShibTranslator e = (OxAuthToShibTranslator) c.newInstance();
                if (e instanceof EnvironmentAware) {
                    ((EnvironmentAware) e).setEnvironment(environment);
                }
                translators.add(e);
                logger.debug("Added translator class {}", classname);
            } catch (final Exception ex) {
                logger.error("Error building oxAuth to Shib translator with name: " + classname, ex);
            }
        }
    }

    private void loadErrorPage(final HttpServletRequest request, final HttpServletResponse response) {
        final RequestDispatcher requestDispatcher = request.getRequestDispatcher("/no-conversation-state.jsp");
        try {
            requestDispatcher.forward(request, response);
        } catch (final Exception ex) {
            logger.error("Error rendering the empty conversation state (shib-oxauth-authn3) error view.");
            response.resetBuffer();
            response.setStatus(404);
        }
    }

}
