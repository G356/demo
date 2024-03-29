package com.security.demo.config;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private static final String BODY_ATTRIBUTE = CustomAuthenticationFilter.class.getSimpleName() + ".body";
	@Autowired
	private ObjectMapper objectMapper;
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		log.info("token : "+((CsrfToken)request.getAttribute("_csrf")).getToken());
		// Parse the request body as a HashMap and populate a request attribute
		if (requiresAuthentication(request, response)) {
			UsernamePasswordRequest usernamePasswordRequest = objectMapper.readValue(request.getInputStream(), UsernamePasswordRequest.class);
			request.setAttribute(BODY_ATTRIBUTE, usernamePasswordRequest);
		}
		super.doFilter(req, res, chain);
	}
	protected String obtainUsername(HttpServletRequest request) {
		UsernamePasswordRequest usernamePasswordRequest = (UsernamePasswordRequest) request.getAttribute(BODY_ATTRIBUTE);
		return usernamePasswordRequest.get(getUsernameParameter());
	}
	protected String obtainPassword(HttpServletRequest request) {
		UsernamePasswordRequest usernamePasswordRequest = (UsernamePasswordRequest) request.getAttribute(BODY_ATTRIBUTE);
		return usernamePasswordRequest.get(getPasswordParameter());
	}
	private static class UsernamePasswordRequest extends HashMap<String, String> {
		// Nothing, just a type marker
	}
}
