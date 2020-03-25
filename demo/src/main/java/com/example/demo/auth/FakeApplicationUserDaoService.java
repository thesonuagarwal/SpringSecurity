package com.example.demo.auth;

import static com.example.demo.security.ApplicationUserRole.ADMIN;
import static com.example.demo.security.ApplicationUserRole.ADMINTRAINEE;
import static com.example.demo.security.ApplicationUserRole.STUDENT;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	
	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		// TODO Auto-generated method stub
		return getApplicationUsers().stream()
									.filter(applicationUser -> username.equals(applicationUser.getUsername()))
									.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers(){
		ApplicationUser user1 = new ApplicationUser("annasmith"
								, passwordEncoder.encode("password")
								, true
								, true
								, true
								, true
								, STUDENT.getGrantedAuthorities());
		ApplicationUser user2 = new ApplicationUser("linda"
				, passwordEncoder.encode("password")
				, true
				, true
				, true
				, true
				, ADMIN.getGrantedAuthorities());
		
		ApplicationUser user3 = new ApplicationUser("tom"
				, passwordEncoder.encode("password")
				, true
				, true
				, true
				, true
				, ADMINTRAINEE.getGrantedAuthorities());
		
		List<ApplicationUser> applicationUsers = Lists.newArrayList(user1,user2,user3);
		return applicationUsers;		
	}

}
