package no.tusla;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.web.filter.CommonsRequestLoggingFilter; 
@Configuration
public class WebSecurityConfigurer extends GlobalAuthenticationConfigurerAdapter
{
	
	@Override
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
		.withUser("aniket")
		.password("aniket")
		.roles("USER")
		.and()		
		.withUser("levent")
		.password("levent")
		.roles("USER")
		.and()
		.withUser("jonathan")
		.password("jonathan")
		.roles("USER")
		.and()
		.withUser("waqar")
		.password("waqar")
		.roles("USER")
		.and()		
		.withUser("henrik")
		.password("henrik")
		.roles("USER", "ADMIN");
	}  
	
	 @Bean
	public CommonsRequestLoggingFilter requestLoggingFilter()
	{
		CommonsRequestLoggingFilter crlf = new CommonsRequestLoggingFilter();
		crlf.setIncludeClientInfo(true);
		crlf.setIncludeQueryString(true);
		crlf.setIncludePayload(true);
		crlf.setIncludeHeaders(true);
		return crlf;
	}
	 
}
