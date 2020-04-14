package no.tusla;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
@Configuration
public class Oauth2Config  extends AuthorizationServerConfigurerAdapter
{	
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager);
	}
	
	 @Override
     public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory().withClient("springsecurity")
        		.secret("Teno2019")
                .authorizedGrantTypes("client_credentials","password","authorization_code")	    //add refresh_token grant if you need refresh token              
                .scopes("read-photos", "read-metadata")
                .redirectUris("http://localhost:8080/redirect");
    }
	 
	 @Override
	 public void configure(AuthorizationServerSecurityConfigurer oauthServer)
	            throws Exception {
	        oauthServer
	                .tokenKeyAccess("permitAll()")
	                .checkTokenAccess("permitAll()");
	    }
}
