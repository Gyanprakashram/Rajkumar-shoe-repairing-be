package com.rajkumar.shoe;
import com.rajkumar.shoe.Models.AppUser;
import com.rajkumar.shoe.Models.Sessions;
import com.rajkumar.shoe.Models.UserSession;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.*;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.security.Key;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.Instant;
import java.util.*;

public class Sec {
  private static final Logger log=LoggerFactory.getLogger(Sec.class);
  @Component public static class Jwt {
    final Key key;
    final long expirationMs;
    public Jwt(@Value("${app.jwt-secret}") String s,@Value("${app.jwt-expiration-ms}") long expirationMs){
      key=Keys.hmacShaKeyFor(s.getBytes());
      if(expirationMs<1) throw new IllegalArgumentException("JWT expiration must be positive");
      this.expirationMs=expirationMs;
    }
    public String make(AppUser u,String sessionId){ return Jwts.builder().setSubject(String.valueOf(u.id))
      .claim("role",u.role).claim("sid",sessionId)
      .setIssuedAt(new Date())
      .setExpiration(new Date(System.currentTimeMillis()+expirationMs)).signWith(key).compact(); }
    public Claims parse(String t){
      Claims claims=Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(t).getBody();
      Date issued=claims.getIssuedAt();
      if(issued==null||issued.getTime()<System.currentTimeMillis()-expirationMs
          ||claims.get("sid",String.class)==null)
        throw new JwtException("Session expired");
      return claims;
    } }

  @Component public static class JwtFilter extends OncePerRequestFilter {
    final Jwt jwt; final Sessions sessions; final long idleTimeoutMs;
    public JwtFilter(Jwt j,Sessions sessions,@Value("${app.session-idle-timeout-ms}") long idleTimeoutMs){
      jwt=j; this.sessions=sessions; this.idleTimeoutMs=idleTimeoutMs;
    }
    @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain c) throws ServletException,IOException {
      String h=req.getHeader("Authorization");
      if(h!=null&&h.startsWith("Bearer ")){ try{ Claims cl=jwt.parse(h.substring(7));
        String sessionId=cl.get("sid",String.class);
        UserSession session=sessions.findById(sessionId).orElseThrow(()->new JwtException("Session expired"));
        LocalDateTime now=LocalDateTime.now();
        if(session.lastActivity==null||Duration.between(session.lastActivity,now).toMillis()>=idleTimeoutMs){
          sessions.delete(session);
          throw new JwtException("Session expired");
        }
        session.lastActivity=now;
        sessions.save(session);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(Long.valueOf(cl.getSubject()),null,
          List.of(new SimpleGrantedAuthority("ROLE_"+cl.get("role",String.class))))); }
        catch(JwtException|IllegalArgumentException ex){
          log.warn("jwt_authentication_rejected requestId={} exception={}",
              req.getAttribute(RequestTraceFilter.REQUEST_ID_ATTRIBUTE),TraceLogSupport.safeException(ex));
        }catch(RuntimeException ex){
          log.error("jwt_authentication_failed requestId={} exception={}",
              req.getAttribute(RequestTraceFilter.REQUEST_ID_ATTRIBUTE),TraceLogSupport.safeException(ex));
          TraceLogSupport.logStack(log,"jwt_authentication_failure_stack",ex);
        } }
      c.doFilter(req,res); } }

  @Configuration public static class Cfg {
    @Bean PasswordEncoder encoder(){ return new BCryptPasswordEncoder(); }
    @Bean UserDetailsService unusedFormLoginUserDetailsService(){
      return username->{throw new UsernameNotFoundException("Form-based authentication is not configured.");};
    }
    @Bean CorsConfigurationSource corsConfigurationSource(@Value("${app.cors-origin}") String origin){
      CorsConfiguration c=new CorsConfiguration();
      List<String> allowedOrigins=Arrays.stream(origin.split(","))
        .map(String::trim).filter(x->!x.isEmpty()).toList();
      c.setAllowedOrigins(allowedOrigins);
      c.setAllowedMethods(List.of("*") );
      c.setAllowedHeaders(List.of("*"));
      c.setExposedHeaders(List.of("X-Payload-Encryption",RequestTraceFilter.REQUEST_ID_HEADER));
      c.setAllowCredentials(true);
      UrlBasedCorsConfigurationSource s=new UrlBasedCorsConfigurationSource(); s.registerCorsConfiguration("/**",c); return s; }
    @Bean SecurityFilterChain chain(HttpSecurity h,JwtFilter f,ObjectMapper mapper,
        @Value("${app.api-encryption.enabled:false}") boolean payloadEncryptionEnabled,
        @Value("${app.api-encryption.key:}") String payloadEncryptionKey) throws Exception {
      h.csrf(c->c.disable()).cors(Customizer.withDefaults())
       .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
       .authorizeHttpRequests(a->a.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
         .requestMatchers(HttpMethod.OPTIONS,"/**").permitAll()
         .requestMatchers("/api/auth/**").permitAll()
         .requestMatchers(HttpMethod.GET,"/api/products/**","/api/settings/public","/api/staticdata").permitAll()
         .requestMatchers("/api/admin/**").hasAuthority("ROLE_ADMIN")
         .anyRequest().authenticated())
       .exceptionHandling(e->e
         .authenticationEntryPoint((request,response,exception)->writeSecurityError(mapper,request,response,
             HttpStatus.UNAUTHORIZED,"Authentication is required to access this resource."))
         .accessDeniedHandler((request,response,exception)->writeSecurityError(mapper,request,response,
             HttpStatus.FORBIDDEN,"You are not authorized to perform this action.")))
       .addFilterBefore(f,UsernamePasswordAuthenticationFilter.class);
      if(payloadEncryptionEnabled){
        h.addFilterBefore(new PayloadEncryptionFilter(mapper,payloadEncryptionKey),JwtFilter.class);
      }
      return h.build(); }

    private static void writeSecurityError(ObjectMapper mapper,HttpServletRequest request,
        HttpServletResponse response,HttpStatus status,String message) throws IOException {
      Object id=request.getAttribute(RequestTraceFilter.REQUEST_ID_ATTRIBUTE);
      String requestId=id instanceof String value?value:"unavailable";
      if(status==HttpStatus.UNAUTHORIZED)
        log.warn("security_authentication_required requestId={}",requestId);
      else
        log.warn("security_access_denied requestId={}",requestId);
      response.setStatus(status.value());
      response.setContentType("application/json");
      mapper.writeValue(response.getOutputStream(),new ApiExceptionHandler.ApiError(
          Instant.now(),status.value(),status.getReasonPhrase(),message,requestId));
    }
  }
}
