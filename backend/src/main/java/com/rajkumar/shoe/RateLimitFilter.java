package com.rajkumar.shoe;

import com.rajkumar.shoe.config.StaticDataConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE+20)
public class RateLimitFilter extends OncePerRequestFilter {
  private static final long WINDOW_MS=60_000;
  private final StaticDataConfig config;
  private final ConcurrentHashMap<String,Window> windows=new ConcurrentHashMap<>();
  private final AtomicLong lastCleanup=new AtomicLong();

  public RateLimitFilter(StaticDataConfig config){ this.config=config; }

  @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)
      throws ServletException,IOException {
    String path=request.getRequestURI();
    if(!path.startsWith("/api/")){chain.doFilter(request,response);return;}
    String group=group(path,request.getMethod());
    int limit=limit(group);
    String key=group+"|"+clientAddress(request);
    long now=System.currentTimeMillis();
    Window window=windows.compute(key,(ignored,current)->current==null||now-current.startedAt>=WINDOW_MS
      ?new Window(now):current);
    boolean allowed;
    synchronized(window){allowed=++window.requests<=limit;}
    if(!allowed){
      response.setStatus(429);
      response.setHeader("Retry-After","60");
      response.setContentType("application/json");
      response.setCharacterEncoding("UTF-8");
      response.getWriter().write("{\"status\":429,\"error\":\"Too Many Requests\",\"message\":\"Too many requests. Please wait a minute and try again.\"}");
      return;
    }
    long previousCleanup=lastCleanup.get();
    if(windows.size()>10_000&&now-previousCleanup>=WINDOW_MS&&lastCleanup.compareAndSet(previousCleanup,now))
      windows.entrySet().removeIf(entry->now-entry.getValue().startedAt>=WINDOW_MS);
    chain.doFilter(request,response);
  }

  private String group(String path,String method){
    if(path.startsWith("/api/auth/"))return "auth";
    if(path.equals("/api/orders")&&"POST".equals(method))return "orders";
    if(path.matches("/api/orders/[^/]+/(payment|quote-response)")&&"POST".equals(method))return "orders";
    return "api";
  }

  private int limit(String group){
    return switch(group){
      case "auth"->config.rateLimit("rate-limit.auth-per-minute",10);
      case "orders"->config.rateLimit("rate-limit.order-per-minute",10);
      default->config.rateLimit("rate-limit.api-per-minute",120);
    };
  }

  private static String clientAddress(HttpServletRequest request){return request.getRemoteAddr();}

  private static final class Window{
    private final long startedAt;
    private int requests;
    private Window(long startedAt){this.startedAt=startedAt;}
  }
}
