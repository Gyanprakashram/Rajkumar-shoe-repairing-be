package com.rajkumar.shoe;

import org.slf4j.Logger;

final class TraceLogSupport {
  private TraceLogSupport() {}

  static String safeException(Throwable error) {
    return error == null ? "unknown" : error.getClass().getName();
  }

  static void logStack(Logger logger, String event, Throwable error) {
    Throwable current = error;
    StringBuilder causes = new StringBuilder();
    StringBuilder frames = new StringBuilder();
    int causeDepth = 0;
    while (current != null && causeDepth < 5) {
      if (causes.length() > 0) causes.append("->");
      causes.append(current.getClass().getName());
      StackTraceElement[] stack = current.getStackTrace();
      for (int i = 0; i < Math.min(stack.length, 12); i++) {
        if (frames.length() > 0) frames.append(" | ");
        frames.append(stack[i].getClassName()).append('.').append(stack[i].getMethodName())
            .append(':').append(stack[i].getLineNumber());
      }
      current = current.getCause();
      causeDepth++;
    }
    logger.error("{} exceptionTypes={} frames={}", event, causes, frames);
  }
}
