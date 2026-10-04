package com.rajkumar.shoe;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class TraceLoggingAspect {
  private static final Logger log = LoggerFactory.getLogger(TraceLoggingAspect.class);

  @Around("""
      execution(public * com.rajkumar.shoe..*(..)) &&
      (within(@org.springframework.stereotype.Service *) ||
       within(@org.springframework.web.bind.annotation.RestController *) ||
       within(com.rajkumar.shoe.notification.OrderNotificationChannels))
      """)
  public Object traceMethod(ProceedingJoinPoint joinPoint) throws Throwable {
    String method = joinPoint.getSignature().toShortString();
    int argumentCount = joinPoint.getArgs().length;
    long startedAt = System.nanoTime();
    log.info("method_entered method={} argumentCount={}", method, argumentCount);
    try {
      Object result = joinPoint.proceed();
      long durationMs = (System.nanoTime() - startedAt) / 1_000_000;
      log.info("method_exited method={} durationMs={}", method, durationMs);
      return result;
    } catch (Throwable error) {
      long durationMs = (System.nanoTime() - startedAt) / 1_000_000;
      log.error("method_failed method={} durationMs={} exception={}",
          method, durationMs, TraceLogSupport.safeException(error));
      TraceLogSupport.logStack(log, "method_failure_stack method=" + method, error);
      throw error;
    }
  }
}
