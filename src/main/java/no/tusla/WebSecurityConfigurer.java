package no.tusla;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Configuration
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("aniket").password("aniket").roles("USER").build());
		manager.createUser(User.withUsername("admin").password("admin").roles("ADMIN").build());
		manager.createUser(User.withUsername("api").password("").roles("API").build());
		manager.createUser(User.withUsername("apotek.no").password("").roles("PHARMACY").build());
		return manager;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();
		return encoder;
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public CommonsRequestLoggingFilter requestLoggingFilter() {
		CommonsRequestLoggingFilter crlf = new CommonsRequestLoggingFilter();
		crlf.setIncludeClientInfo(true);
		crlf.setIncludeQueryString(true);
		crlf.setIncludePayload(true);
		crlf.setIncludeHeaders(true);
		return crlf;
	}
	

}
