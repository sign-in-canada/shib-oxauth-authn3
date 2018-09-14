## A Shibboleth IdP v3.X plugin for authentication via an external oxAuth Server

This is a Shibboleth IDP external authentication plugin that delegates the authentication to an external 
Central Authentication Server. The biggest advantage of using this component over the plain 
`REMOTE_USER` header solution provided by Shibboleth is the ability to deligate oxAuth Server user authentication,
plus the ability to share with oxAuth server the EntityID of the relying application.

The plugin consists of 2 components:
* A library (.jar) file that provides an IDP side servlet that acts as a bridge between oxAuth and the IDP
* Spring Webflow definition file (and bean definition file) that invokes the shib-oxauth-authn3 library.

Software Requirements
-------------------------------------------------------------
This minimum supported version of Shibboleth Identity Provider is `3.3.0`

Installation
---------------------------------------------------------------

#### Overview

1. Copy the Spring Webflow files, jsp, and included jar files into the IDP_HOME.
2. Update the IdP's `web.xml`. (optional)
3. Update the IdP's `idp.properties` file.
4. Update the IdP's `general-authn.xml` file.
5. Rebuild the war file.

#### Copy the Spring Webflow files into the IDP_HOME
Copy the two xml files from the IDP_HOME directory (in the src tree) to the corresponding layout in your Shibboleth IdP home directory.

#### Update the IdP's `web.xml` (optional)
> The servlet will register itself with the container when running under a Servlet 3.0 compliant container (such as Jetty 9).
This step is provided for legacy reasons.

Add the ShibOxAuth Auth Servlet entry in `IDP_HOME/edit-webapp/WEB-INF/web.xml` (Copy from `IDP_HOME/webapp/WEB-INF/web.xml`, if necessary.)

Example snippet `web.xml`:

```xml
...
    <!-- Servlet for receiving a callback from an external oxAuth Server and continues the IdP login flow -->
    <servlet>
        <servlet-name>ShibOxAuth Auth Servlet</servlet-name>
        <servlet-class>org.gluu.idp.externalauth.ShibOxAuthAuthServlet</servlet-class>
        <load-on-startup>2</load-on-startup>
    </servlet>
    <servlet-mapping>
        <servlet-name>ShibOxAuth Auth Servlet</servlet-name>
        <url-pattern>/Authn/oxAuth/*</url-pattern>
    </servlet-mapping>
...
```

#### Update the IdP's idp.properties file

1. Set the `idp.authn.flows` to `ShibOxAuth`. Or, for advance cases, add `ShibOxAuth` to the list.
1. Add the additional properties.

```properties   
...
# Regular expression matching login flows to enable, e.g. IPAddress|Password
#idp.authn.flows = Password
idp.authn.flows = ShibOxAuth

# By default you always get the AuthenticatedNameTranslator, add additional code to cover your custom needs.
# Takes a comma separated list of fully qualified class names
# shib.oxauth.oxAuthToShibTranslators = com.your.institution.MyCustomNamedTranslatorClass
...
```

#### Update the IdP's `general-authn.xml` file.
Register the module with the IdP by adding the `authn/ShibOxAuth` bean in `IDP_HOME/conf/authn/general-authn.xml`:

```xml
...
    <util:list id="shibboleth.AvailableAuthenticationFlows">

        <bean id="authn/oxAuth" parent="shibboleth.AuthenticationFlow"
                p:forcedAuthenticationSupported="true"
                p:nonBrowserSupported="false" />
...
```


#### Rebuild the war file
From the `IDP_HOME/bin` directory, run `./build.sh` or `build.bat` to rebuild the `idp.war`. Redeploy if necessary.

Release Notes
-------------------------------------------------------------
See [here](https://github.com/GluuFederation/shib-oxauth-authn3/releases/).

Developer Notes
-------------------------------------------------------------
The project distributables can be built using `./gradlew clean build`. The artifacts will be in `build/distributions`.

