package com.rajkumar.shoe;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestTraceFilter extends OncePerRequestFilter {
  private static final Logger log = LoggerFactory.getLogger(RequestTraceFilter.class);
  public static final String REQUEST_ID_HEADER = "X-Request-ID";
  public static final String REQUEST_ID_ATTRIBUTE = RequestTraceFilter.class.getName() + ".requestId";

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String requestId = UUID.randomUUID().toString();
    String path = safePath(request.getRequestURI());
    long startedAt = System.nanoTime();
    MDC.put("requestId", requestId);
    request.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);
    response.setHeader(REQUEST_ID_HEADER, requestId);
    try {
      log.info("http_request_started method={} path={}", request.getMethod(), path);
      chain.doFilter(request, response);
    } catch (ServletException | IOException | RuntimeException ex) {
      log.error("http_request_failed method={} path={} exception={}",
          request.getMethod(), path, TraceLogSupport.safeException(ex));
      TraceLogSupport.logStack(log, "http_request_stack", ex);
      throw ex;
    } catch (Error error) {
      log.error("http_request_failed method={} path={} exception={}",
          request.getMethod(), path, TraceLogSupport.safeException(error));
      TraceLogSupport.logStack(log, "http_request_stack", error);
      throw error;
    } finally {
      long durationMs = (System.nanoTime() - startedAt) / 1_000_000;
      int status = response.getStatus();
      if (status >= 500) {
        log.error("http_request_completed method={} path={} status={} durationMs={}",
            request.getMethod(), path, status, durationMs);
      } else if (status >= 400) {
        log.warn("http_request_completed method={} path={} status={} durationMs={}",
            request.getMethod(), path, status, durationMs);
      } else {
        log.info("http_request_completed method={} path={} status={} durationMs={}",
            request.getMethod(), path, status, durationMs);
      }
      MDC.remove("requestId");
    }
  }

  private static String safePath(String path) {
    if (path == null) return "/";
    String safe = path.replaceAll("[\\r\\n\\t]", "_");
    return safe.length() > 256 ? safe.substring(0, 256) : safe;
  }
}
