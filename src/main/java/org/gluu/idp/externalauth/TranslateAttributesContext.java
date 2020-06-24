package org.gluu.idp.externalauth;

import java.io.Serializable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.gluu.oxauth.client.auth.user.UserProfile;

/**
 * Translate attributes context
 *
 * @author Yuriy Movchan
 * @version 0.1, 06/22/2020
 */
public class TranslateAttributesContext implements Serializable {

	private static final long serialVersionUID = 1922377169827670256L;

	private HttpServletRequest request;
	private HttpServletResponse response;
	private UserProfile userProfile;
	private String authenticationKey;

	public TranslateAttributesContext(HttpServletRequest request, HttpServletResponse response, UserProfile userProfile,
			String authenticationKey) {
		this.request = request;
		this.response = response;
		this.userProfile = userProfile;
		this.authenticationKey = authenticationKey;
	}

	public HttpServletRequest getRequest() {
		return request;
	}

	public HttpServletResponse getResponse() {
		return response;
	}

	public UserProfile getUserProfile() {
		return userProfile;
	}

	public String getAuthenticationKey() {
		return authenticationKey;
	}

}
