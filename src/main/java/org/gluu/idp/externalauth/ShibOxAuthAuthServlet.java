package org.gluu.idp.externalauth;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.gluu.context.J2EContext;
import org.gluu.context.WebContext;
import org.gluu.idp.externalauth.openid.client.IdpAuthClient;
import org.gluu.oxauth.client.auth.principal.OpenIdCredentials;
import org.gluu.oxauth.client.auth.user.UserProfile;
import org.gluu.oxauth.model.exception.InvalidJwtException;
import org.gluu.oxauth.model.jwt.Jwt;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.web.context.WebApplicationContext;

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
    private final String OXAUTH_ATTRIBIUTE_SEND_END_SESSION_REQUEST = "sendEndSession";

    @Autowired
    @Qualifier("idpAuthClient")
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
            final String requestUrl = request.getRequestURL().toString();
            logger.trace("Get request to: '{}'", requestUrl);

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
            final boolean authorizationResponse = idpAuthClient.isAuthorizationResponse(context);

            HttpServletRequest externalRequest = request;
            if (authorizationResponse) {
                try {
                    final Jwt jwt = Jwt.parse(idpAuthClient.getRequestState(context));

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
                    logger.debug("State is not in JWT format", ex);
                }
            }

            // Get authentication key from request 
            final String authenticationKey = ExternalAuthentication.startExternalAuthentication(externalRequest);

            // Get external authentication properties
            final boolean force = Boolean.parseBoolean(request.getAttribute(ExternalAuthentication.FORCE_AUTHN_PARAM).toString());

            // It's an authentication
            if (!authorizationResponse) {
                logger.debug("Initiating oxAuth login redirect");
                startLoginRequest(request, response, force);
                return;
            }

            logger.info("Procession authorization response");

            // Check if oxAuth request state is correct
            if (!idpAuthClient.isValidRequestState(context)) {
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
            final WebContext context = new J2EContext(request, response);

            final OpenIdCredentials openIdCredentials = idpAuthClient.getCredentials(context);
            logger.debug("Client name : '{}'", openIdCredentials.getClientName());

            final UserProfile userProfile = idpAuthClient.getUserProfile(openIdCredentials, context);
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
            final WebContext context = new J2EContext(request, response);

            final Map<String, String> customResponseHeaders = new HashMap<String, String>();
            final String convId = request.getParameter(ExternalAuthentication.CONVERSATION_KEY);
            customResponseHeaders.put(ExternalAuthentication.CONVERSATION_KEY, convId);
            
            final Map<String, String> customParameters = new HashMap<String, String>();
            final String relyingPartyId = request.getAttribute(ExternalAuthentication.RELYING_PARTY_PARAM).toString();
            customParameters.put(OXAUTH_PARAM_ENTITY_ID, relyingPartyId);
            
            try {
                ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(convId, request);
                AuthnRequest authnRequest = (AuthnRequest) prc.getInboundMessageContext().getMessage();
                if (null != authnRequest) {
                    RequestedAuthnContext authnContext = authnRequest.getRequestedAuthnContext();
                    if (null != authnContext) {
                        String acrs = authnContext.getAuthnContextClassRefs().stream()
                            .map(AuthnContextClassRef::getAuthnContextClassRef).collect(Collectors.joining(" "));
                            customParameters.put("acr_values", acrs);
                    }
                    NameIDPolicy nameIDPolicy = authnRequest.getNameIDPolicy();
                    String spNameQualifier;
                    if (null != nameIDPolicy) {
                        spNameQualifier = nameIDPolicy.getSPNameQualifier();
                        if (null == spNameQualifier) {
                            spNameQualifier = relyingPartyId;
                        }
                        customParameters.put("spNameQualifier", spNameQualifier);
                    }
                }
            } catch (Exception e) {
                logger.error("Unable to process AuthnRequest", e);
            }           

            final String loginUrl = idpAuthClient.getRedirectionUrl(context, customResponseHeaders, customParameters, force);
            logger.debug("Generated redirection Url", loginUrl);

            logger.debug("loginUrl: {}", loginUrl);
            response.sendRedirect(loginUrl);
        } catch (final IOException ex) {
            logger.error("Unable to redirect to oxAuth from ShibOxAuth", ex);
        }
    }

    protected void processLogoutRequest(final HttpServletRequest request, final HttpServletResponse response) {
        try {
            // Web context
            final WebContext context = new J2EContext(request, response);

            final String logoutUrl = idpAuthClient.getLogoutRedirectionUrl(context);
            logger.debug("Generated logout redirection Url", logoutUrl);
            

            logger.debug("logoutUrl: {}", logoutUrl);
            response.sendRedirect(logoutUrl);

            idpAuthClient.clearAuthorized(context);
            idpAuthClient.setAttribute(context, OXAUTH_ATTRIBIUTE_SEND_END_SESSION_REQUEST, Boolean.TRUE);
            logger.debug("Client authorization is removed (set null id_token in session)");
        } catch (final IOException ex) {
            logger.error("Unable to redirect to oxAuth from ShibOxAuth", ex);
        }
    }

    protected void processSsoLogoutRequest(final HttpServletRequest request, final HttpServletResponse response) {
        try {
            // Web context
            final WebContext context = new J2EContext(request, response);
            final Object sendEndSession = idpAuthClient.getAttribute(context, OXAUTH_ATTRIBIUTE_SEND_END_SESSION_REQUEST);
            if (Boolean.TRUE.equals(sendEndSession)) {
                idpAuthClient.setAttribute(context, OXAUTH_ATTRIBIUTE_SEND_END_SESSION_REQUEST, null);
                logger.debug("Client send end_session request. Ignoring OP initiated logout request");
                return;
            }

            final String logoutUrl = "/idp/profile/Logout";
            logger.debug("logoutUrl: {}", logoutUrl);
            response.sendRedirect(logoutUrl);

            idpAuthClient.clearAuthorized(context);
            logger.debug("Client authorization is removed (set null id_token in session)");
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
