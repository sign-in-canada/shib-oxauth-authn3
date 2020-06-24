package org.gluu.idp.externalauth;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.gluu.context.J2EContext;
import org.gluu.context.WebContext;
import org.gluu.idp.consent.processor.PostProcessAttributesContext;
import org.gluu.idp.externalauth.openid.client.IdpAuthClient;
import org.gluu.idp.script.service.IdpCustomScriptManager;
import org.gluu.idp.script.service.external.IdpExternalScriptService;
import org.gluu.oxauth.client.auth.principal.OpenIdCredentials;
import org.gluu.oxauth.client.auth.user.UserProfile;
import org.gluu.oxauth.model.exception.InvalidJwtException;
import org.gluu.oxauth.model.jwt.Jwt;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import net.shibboleth.idp.attribute.context.AttributeContext;
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

    private final Logger LOG = LoggerFactory.getLogger(ShibOxAuthAuthServlet.class);

    private final String OXAUTH_PARAM_ENTITY_ID = "entityId";
    private final String OXAUTH_PARAM_ISSUER_ID = "issuerId";
    private final String OXAUTH_ATTRIBIUTE_SEND_END_SESSION_REQUEST = "sendEndSession";

    private IdpAuthClient authClient;

    private final Set<OxAuthToShibTranslator> translators = new HashSet<OxAuthToShibTranslator>();

	private IdpCustomScriptManager customScriptManager;
	private IdpExternalScriptService externalScriptService;

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);

        ServletContext context = getServletContext();

        WebApplicationContext applicationContext = WebApplicationContextUtils.getWebApplicationContext(context);

        this.authClient = (IdpAuthClient) applicationContext.getBean("idpAuthClient");
        this.customScriptManager = (IdpCustomScriptManager) applicationContext.getBean("idpCustomScriptManager");

        // Call custom script manager init to make sure that it initialized
    	this.customScriptManager.init();
    	this.externalScriptService = this.customScriptManager.getIdpExternalScriptService();

		final ApplicationContext ac = (ApplicationContext) context
				.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);

        buildTranslators(ac.getEnvironment());
    }

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException {
        try {
            final String requestUrl = request.getRequestURL().toString();
            LOG.trace("Get request to: '{}'", requestUrl);

            boolean logoutEndpoint = requestUrl.endsWith("/logout");
            if (logoutEndpoint ) {
                processLogoutRequest(request, response);
                return;
            }

            boolean ssoLogoutEndpoint = requestUrl.endsWith("/ssologout");
            if (ssoLogoutEndpoint ) {
                processSsoLogoutRequest(request, response);
                return;
            }

            // Web context
            final WebContext context = new J2EContext(request, response);
            final boolean authorizationResponse = authClient.isAuthorizationResponse(context);

            HttpServletRequest externalRequest = request;
            if (authorizationResponse) {
                try {
                    final Jwt jwt = Jwt.parse(authClient.getRequestState(context));

                    externalRequest = new HttpServletRequestWrapper(request) {
                        @Override
                        public String getParameter(String name) {
                            if (jwt.getClaims().hasClaim(name)) {
                                return jwt.getClaims().getClaimAsString(name);
                            }

                            return super.getParameter(name);
                        }
                    };
                } catch (InvalidJwtException ex) {
                    LOG.debug("State is not in JWT format", ex);
                }
            }

            // Get authentication key from request 
            final String authenticationKey = ExternalAuthentication.startExternalAuthentication(externalRequest);

            // Get external authentication properties
            final boolean force = Boolean.parseBoolean(request.getAttribute(ExternalAuthentication.FORCE_AUTHN_PARAM).toString());

            // It's an authentication
            if (!authorizationResponse) {
                LOG.debug("Initiating oxAuth login redirect");
                startLoginRequest(request, response, force);
                return;
            }

            LOG.info("Procession authorization response");

            // Check if oxAuth request state is correct
            if (!authClient.isValidRequestState(context)) {
                LOG.error("The state in session and in request are not equals");

                // Re-init login page
                startLoginRequest(request, response, force);
                return;
            }

            processAuthorizationResponse(request, response, authenticationKey);

        } catch (final ExternalAuthenticationException ex) {
            LOG.warn("Error processing oxAuth authentication request", ex);
            loadErrorPage(request, response);

        } catch (final Exception ex) {
            LOG.error("Something unexpected happened", ex);
            request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.AUTHN_EXCEPTION);
        }
    }

    private void processAuthorizationResponse(final HttpServletRequest request, final HttpServletResponse response, final String authenticationKey)
            throws ExternalAuthenticationException, IOException {
        try {
            // Web context
            final WebContext context = new J2EContext(request, response);

            final OpenIdCredentials openIdCredentials = authClient.getCredentials(context);
            LOG.debug("Client name : '{}'", openIdCredentials.getClientName());

            final UserProfile userProfile = authClient.getUserProfile(openIdCredentials, context);
            LOG.debug("User profile : {}", userProfile);

            if (userProfile == null) {
                LOG.error("Token validation failed, returning InvalidToken");
                request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "InvalidToken");
            } else {
        		// Return if script(s) not exists or invalid
            	boolean result = false;
        		if (this.externalScriptService.isEnabled()) {
        			TranslateAttributesContext translateAttributesContext = buildContext(request, response, userProfile, authenticationKey);
        			result = this.externalScriptService.executeExternalTranslateAttributesMethod(translateAttributesContext);
        		}
        		
        		if (!result) {
        			LOG.trace("Using default translate attributes method");

        			for (final OxAuthToShibTranslator translator : translators) {
                        translator.doTranslation(request, response, userProfile, authenticationKey);
                    }
        		}

            }
        } catch (final Exception ex) {
            LOG.error("Token validation failed, returning InvalidToken", ex);
            request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "InvalidToken");
        } finally {
            ExternalAuthentication.finishExternalAuthentication(authenticationKey, request, response);
        }
    }

    protected void startLoginRequest(final HttpServletRequest request, final HttpServletResponse response, final Boolean force) {
        try {
            // Web context
            final WebContext context = new J2EContext(request, response);

            final Map<String, String> customResponseHeaders = new HashMap<String, String>();
            final String convId = request.getParameter(ExternalAuthentication.CONVERSATION_KEY);
            customResponseHeaders.put(ExternalAuthentication.CONVERSATION_KEY, convId);
            
            final Map<String, String> customParameters = new HashMap<String, String>();
            final String relayingPartyId = request.getAttribute(ExternalAuthentication.RELYING_PARTY_PARAM).toString();
            customParameters.put(OXAUTH_PARAM_ENTITY_ID, relayingPartyId);
            
            try {
                ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(convId, request);
                AuthnRequest authnRequest = (AuthnRequest) prc.getInboundMessageContext().getMessage();
                if (authnRequest != null) {
                    RequestedAuthnContext authnContext = authnRequest.getRequestedAuthnContext();
                    Issuer issuer = authnRequest.getIssuer();
                    if (issuer != null) {
                    	customParameters.put(OXAUTH_PARAM_ISSUER_ID, issuer.getValue());
                    }
                    if (null != authnContext) {
                        String acrs = authnContext.getAuthnContextClassRefs().stream()
                            .map(AuthnContextClassRef::getAuthnContextClassRef).collect(Collectors.joining(" "));
                        customParameters.put("acr_values", acrs);
                    }
                }
            } catch (Exception e) {
                LOG.error("Unable to process to AuthnContextClassRef", e);
            }           

            final String loginUrl = authClient.getRedirectionUrl(context, customResponseHeaders, customParameters, force);
            LOG.debug("Generated redirection Url", loginUrl);

            LOG.debug("loginUrl: {}", loginUrl);
            response.sendRedirect(loginUrl);
        } catch (final IOException ex) {
            LOG.error("Unable to redirect to oxAuth from ShibOxAuth", ex);
        }
    }

    protected void processLogoutRequest(final HttpServletRequest request, final HttpServletResponse response) {
        try {
            // Web context
            final WebContext context = new J2EContext(request, response);

            final String logoutUrl = authClient.getLogoutRedirectionUrl(context);
            LOG.debug("Generated logout redirection Url", logoutUrl);
            

            LOG.debug("logoutUrl: {}", logoutUrl);
            response.sendRedirect(logoutUrl);

            authClient.clearAuthorized(context);
            authClient.setAttribute(context, OXAUTH_ATTRIBIUTE_SEND_END_SESSION_REQUEST, Boolean.TRUE);
            LOG.debug("Client authorization is removed (set null id_token in session)");
        } catch (final IOException ex) {
            LOG.error("Unable to redirect to oxAuth from ShibOxAuth", ex);
        }
    }

    protected void processSsoLogoutRequest(final HttpServletRequest request, final HttpServletResponse response) {
        try {
            // Web context
            final WebContext context = new J2EContext(request, response);
            final Object sendEndSession = authClient.getAttribute(context, OXAUTH_ATTRIBIUTE_SEND_END_SESSION_REQUEST);
            if (Boolean.TRUE.equals(sendEndSession)) {
                authClient.setAttribute(context, OXAUTH_ATTRIBIUTE_SEND_END_SESSION_REQUEST, null);
                LOG.debug("Client send end_session request. Ignoring OP initiated logout request");
                return;
            }

            final String logoutUrl = "/idp/profile/Logout";
            LOG.debug("logoutUrl: {}", logoutUrl);
            response.sendRedirect(logoutUrl);

            authClient.clearAuthorized(context);
            LOG.debug("Client authorization is removed (set null id_token in session)");
        } catch (final IOException ex) {
            LOG.error("Unable to redirect to oxAuth from ShibOxAuth", ex);
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
                LOG.debug("Loading translator class {}", classname);
                final Class<?> c = Class.forName(classname);
                final OxAuthToShibTranslator e = (OxAuthToShibTranslator) c.newInstance();
                if (e instanceof EnvironmentAware) {
                    ((EnvironmentAware) e).setEnvironment(environment);
                }
                translators.add(e);
                LOG.debug("Added translator class {}", classname);
            } catch (final Exception ex) {
                LOG.error("Error building oxAuth to Shib translator with name: " + classname, ex);
            }
        }
    }

    private void loadErrorPage(final HttpServletRequest request, final HttpServletResponse response) {
        final RequestDispatcher requestDispatcher = request.getRequestDispatcher("/no-conversation-state.jsp");
        try {
            requestDispatcher.forward(request, response);
        } catch (final Exception ex) {
            LOG.error("Error rendering the empty conversation state (shib-oxauth-authn3) error view.");
            response.resetBuffer();
            response.setStatus(404);
        }
    }

	private TranslateAttributesContext buildContext(HttpServletRequest request, HttpServletResponse response, UserProfile userProfile, String authenticationKey) {
		TranslateAttributesContext translateAttributesContext = new TranslateAttributesContext(request, response, userProfile, authenticationKey);

		return translateAttributesContext;
	}

}
