package com.rajkumar.shoe;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.Instant;

@RestControllerAdvice
public class ApiExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

  public record ApiError(Instant timestamp, int status, String error, String message, String requestId) {}

  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<ApiError> responseStatus(ResponseStatusException exception, HttpServletRequest request) {
    HttpStatus status = HttpStatus.valueOf(exception.getStatusCode().value());
    String message = status.is4xxClientError() && exception.getReason() != null
        ? safeMessage(exception.getReason()) : "The request could not be completed.";
    if (status.is5xxServerError()) {
      logFailure("api_expected_status_failure", request, exception);
    }
    return response(status, message, request);
  }

  @ExceptionHandler({
      HttpMessageNotReadableException.class,
      MethodArgumentNotValidException.class,
      MethodArgumentTypeMismatchException.class,
      MaxUploadSizeExceededException.class,
      MissingServletRequestParameterException.class
  })
  public ResponseEntity<ApiError> invalidRequest(Exception exception, HttpServletRequest request) {
    log.warn("api_request_rejected requestId={} path={} exception={}",
        requestId(request), safePath(request), TraceLogSupport.safeException(exception));
    String message = exception instanceof MaxUploadSizeExceededException
        ? "The uploaded file exceeds the allowed size."
        : "The request is invalid. Check the required fields and value formats.";
    return response(HttpStatus.BAD_REQUEST, message, request);
  }

  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ApiError> methodNotAllowed(
      HttpRequestMethodNotSupportedException exception, HttpServletRequest request) {
    return response(HttpStatus.METHOD_NOT_ALLOWED, "The HTTP method is not supported for this endpoint.", request);
  }

  @ExceptionHandler(NoResourceFoundException.class)
  public ResponseEntity<ApiError> notFound(NoResourceFoundException exception, HttpServletRequest request) {
    return response(HttpStatus.NOT_FOUND, "The requested resource was not found.", request);
  }

  @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
  public ResponseEntity<ApiError> unsupportedMediaType(
      HttpMediaTypeNotSupportedException exception, HttpServletRequest request) {
    return response(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "The request content type is not supported.", request);
  }

  @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
  public ResponseEntity<ApiError> notAcceptable(
      HttpMediaTypeNotAcceptableException exception, HttpServletRequest request) {
    return response(HttpStatus.NOT_ACCEPTABLE, "The response format is not supported.", request);
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ApiError> accessDenied(AccessDeniedException exception, HttpServletRequest request) {
    log.warn("api_access_denied requestId={} path={} exception={}",
        requestId(request), safePath(request), TraceLogSupport.safeException(exception));
    return response(HttpStatus.FORBIDDEN, "You are not authorized to perform this action.", request);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiError> unexpected(Exception exception, HttpServletRequest request) {
    logFailure("api_unhandled_exception", request, exception);
    return response(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred. Use the request ID when contacting support.", request);
  }

  private static ResponseEntity<ApiError> response(HttpStatus status, String message, HttpServletRequest request) {
    return ResponseEntity.status(status).body(new ApiError(
        Instant.now(), status.value(), status.getReasonPhrase(), message, requestId(request)));
  }

  private static String requestId(HttpServletRequest request) {
    Object value = request.getAttribute(RequestTraceFilter.REQUEST_ID_ATTRIBUTE);
    return value instanceof String id ? id : "unavailable";
  }

  private static String safePath(HttpServletRequest request) {
    String path = request.getRequestURI();
    if (path == null) return "/";
    String safe = path.replaceAll("[\\r\\n\\t]", "_");
    return safe.length() > 256 ? safe.substring(0, 256) : safe;
  }

  private static String safeMessage(String message) {
    String safe = message.replaceAll("[\\r\\n\\t]", " ").trim();
    return safe.length() > 240 ? safe.substring(0, 240) : safe;
  }

  private static void logFailure(String event, HttpServletRequest request, Throwable exception) {
    log.error("{} requestId={} method={} path={} exception={}", event, requestId(request),
        request.getMethod(), safePath(request), TraceLogSupport.safeException(exception));
    TraceLogSupport.logStack(log, event + "_stack", exception);
  }
}
