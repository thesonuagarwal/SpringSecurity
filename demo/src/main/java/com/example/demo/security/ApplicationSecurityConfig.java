package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static com.example.demo.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserPermission.*;



@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)

public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;
	
	
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService,
			SecretKey secretKey, JwtConfig jwtConfig) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
		this.secretKey = secretKey;
		this.jwtConfig = jwtConfig;
	}

	
	
	/*
	  // Basic authentication(non-Javadoc)
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable() // TODO: rework on it later
			.authorizeRequests()
			.antMatchers("/","index","/css/*","/js/*").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
			.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
			.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
			.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
			.anyRequest()
			.authenticated()
			.and()
			.httpBasic();
	}*/
	
	// using preAuthorise() annotation in StudentManagementController class instead of ant matchers
	// Basic authentication 
	/*@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable() // TODO: rework on it later
			//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
			.authorizeRequests()
			.antMatchers("/","index","/css/*","/js/*").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			//.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
			.anyRequest()
			.authenticated()
			.and()
			.httpBasic();
	}*/
	
	/*
	// form based authentication
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable() // TODO: rework on it later
			//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
			.authorizeRequests()
			.antMatchers("/","index","/css/*","/js/*").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			//.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
			.anyRequest()
			.authenticated() 
			.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()// customized login page
				.defaultSuccessUrl("/courses",true)
				.passwordParameter("password")
				.usernameParameter("username")
			.and()
			.rememberMe()
				.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))// set expiration to 21 days. Default is two units
				.key("somethingverysecured")
				.rememberMeParameter("remember-me")
			.and()
			.logout()
				.logoutUrl("/logout")
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID","remember-me")
				.logoutSuccessUrl("/login");
	}
	*/
	 
	/*
	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		 UserDetails annasmith = User.builder().username("annasmith")
					  .password(passwordEncoder.encode("password"))
					  //.roles(STUDENT.name()) // ROLE_STUDENT
					  .authorities(STUDENT.getGrantedAuthorities())
					  .build();
		 UserDetails linda = User.builder().username("linda")
				  .password(new BCryptPasswordEncoder().encode("password"))
				  //.roles(ADMIN.name()) // ROLE_ADMIN
				  .authorities( ADMIN.getGrantedAuthorities())
				  .build();
		 
		 UserDetails tom = User.builder().username("tom")
				  .password(new BCryptPasswordEncoder().encode("password"))
				  //.roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
				  .authorities(ADMINTRAINEE.getGrantedAuthorities())
				  .build();
		return new InMemoryUserDetailsManager(annasmith,linda,tom);  
	}*/
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable() // TODO: rework on it later
			//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(),jwtConfig,secretKey))
			.addFilterAfter(new JwtTokenVerifier(jwtConfig,secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
			.authorizeRequests()
			.antMatchers("/","index","/css/*","/js/*").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			//.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
			//.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
			.anyRequest()
			.authenticated(); 
			
	}
	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(this.passwordEncoder);
		provider.setUserDetailsService(this.applicationUserService);
		return provider;
	}
	
}
