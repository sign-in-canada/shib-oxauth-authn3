package org.gluu.idp.externalauth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.gluu.oxauth.client.auth.user.UserProfile;

/**
 * This interface defines the public interface for a class that will translate the information from oxAuth to Shib. The translator
 * should only push details into the request and should NOT attempt to call
 * AuthenticationEngine.returnToAuthenticationEngine(request, response);
 * <p>
 * Instance of this type should implement hashcode and equals.
 *
 * @author Yuriy Movchan
 * @version 0.1, 09/13/2018
 */
public interface OxAuthToShibTranslator {
    /**
     * Do the needed translation.
     *
     * @param request           The HttpServletRequest object
     * @param response          The HttpServletResponse object
     * @param userProfile       The oxAuth User Profile after getting id_token
     * @param authenticationKey the authentication key
     * @throws Exception the exception
     */
    void doTranslation(HttpServletRequest request, HttpServletResponse response, UserProfile userProfile, String authenticationKey) throws Exception;
}
