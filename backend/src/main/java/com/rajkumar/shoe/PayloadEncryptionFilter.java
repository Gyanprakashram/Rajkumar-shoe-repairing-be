package com.rajkumar.shoe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ReadListener;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Base64;
import java.util.Enumeration;
import java.util.UUID;

final class PayloadEncryptionFilter extends OncePerRequestFilter {
  private static final Logger log = LoggerFactory.getLogger(PayloadEncryptionFilter.class);
  private static final int IV_LENGTH = 12;
  private static final int TAG_LENGTH_BITS = 128;
  private final ObjectMapper mapper;
  private final SecretKeySpec key;
  private final SecureRandom random = new SecureRandom();

  PayloadEncryptionFilter(ObjectMapper mapper, String encodedKey) {
    this.mapper = mapper;
    byte[] decoded;
    try {
      decoded = Base64.getDecoder().decode(encodedKey);
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException("API_ENCRYPTION_KEY must be Base64-encoded AES key material.", ex);
    }
    if (decoded.length != 32) {
      throw new IllegalArgumentException("API_ENCRYPTION_KEY must decode to exactly 32 bytes for AES-256-GCM.");
    }
    key = new SecretKeySpec(decoded, "AES");
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String apiPrefix = request.getContextPath() + "/api/";
    if (request.getRequestURI().startsWith(apiPrefix)) return false;
    Object originalUri = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
    return originalUri == null || !originalUri.toString().startsWith(apiPrefix);
  }

  @Override
  protected boolean shouldNotFilterErrorDispatch() {
    return false;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    ContentCachingResponseWrapper wrapped = new ContentCachingResponseWrapper(response);
    HttpServletRequest decrypted = null;
    try {
      decrypted = decryptRequest(request);
    } catch (GeneralSecurityException | IllegalArgumentException | IOException ex) {
      log.warn("encrypted_payload_rejected requestId={} exception={}",
          request.getAttribute(RequestTraceFilter.REQUEST_ID_ATTRIBUTE), TraceLogSupport.safeException(ex));
      wrapped.resetBuffer();
      wrapped.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      wrapped.setContentType("application/json");
      wrapped.getWriter().write("{\"message\":\"Encrypted API payload is invalid.\"}");
    }
    if (decrypted != null) chain.doFilter(decrypted, wrapped);

    byte[] body = wrapped.getContentAsByteArray();
    String contentType = wrapped.getContentType();
    if (contentType != null && (contentType.contains("application/json") || contentType.contains("+json"))
        && body.length > 0) {
      try {
        byte[] encrypted = encrypt(body);
        response.setStatus(wrapped.getStatus());
        response.setContentType("text/plain");
        response.setHeader("X-Payload-Encryption", "AES-256-GCM");
        response.setContentLength(encrypted.length);
        response.getOutputStream().write(encrypted);
      } catch (GeneralSecurityException ex) {
        throw new ServletException("Could not encrypt API response.", ex);
      }
    } else {
      wrapped.copyBodyToResponse();
    }
  }

  private HttpServletRequest decryptRequest(HttpServletRequest request)
      throws IOException, GeneralSecurityException {
    byte[] envelope = request.getInputStream().readAllBytes();
    if (envelope.length == 0) return request;
    if (!"AES-256-GCM".equals(request.getHeader("X-Payload-Encryption"))) {
      throw new IllegalArgumentException("Missing API payload encryption header.");
    }

    byte[] clear = decrypt(envelope);
    JsonNode clearJson = mapper.readTree(clear);
    if (clearJson != null && clearJson.path("__multipart").asBoolean(false)) {
      String boundary = "rk-" + UUID.randomUUID();
      byte[] multipart = multipartBody(clearJson, boundary);
      return new BodyRequest(request, multipart, "multipart/form-data; boundary=" + boundary);
    }
    return new BodyRequest(request, clear, "application/json");
  }

  private byte[] multipartBody(JsonNode form, String boundary) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    for (JsonNode entry : form.path("entries")) {
      String name = safeHeader(entry.path("name").asText());
      output.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + name + "\"")
          .getBytes(StandardCharsets.UTF_8));
      if (entry.has("fileName")) {
        String fileName = safeHeader(entry.path("fileName").asText());
        String type = safeHeader(entry.path("contentType").asText("application/octet-stream"));
        output.write(("; filename=\"" + fileName + "\"\r\nContent-Type: " + type + "\r\n\r\n")
            .getBytes(StandardCharsets.UTF_8));
        output.write(Base64.getDecoder().decode(entry.path("value").asText()));
      } else {
        output.write("\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        output.write(entry.path("value").asText().getBytes(StandardCharsets.UTF_8));
      }
      output.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }
    output.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
    return output.toByteArray();
  }

  private static String safeHeader(String value) {
    return value.replace("\r", "").replace("\n", "").replace("\"", "'");
  }

  private byte[] encrypt(byte[] clear) throws GeneralSecurityException {
    byte[] iv = new byte[IV_LENGTH];
    random.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
    byte[] encrypted = cipher.doFinal(clear);
    byte[] result = new byte[iv.length + encrypted.length];
    System.arraycopy(iv, 0, result, 0, iv.length);
    System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
    return Base64.getEncoder().encode(result);
  }

  private byte[] decrypt(byte[] encodedPayload) throws GeneralSecurityException {
    byte[] payload = Base64.getDecoder().decode(new String(encodedPayload, StandardCharsets.US_ASCII).trim());
    if (payload.length <= IV_LENGTH + TAG_LENGTH_BITS / 8) {
      throw new IllegalArgumentException("Invalid AES-GCM payload.");
    }
    byte[] iv = new byte[IV_LENGTH];
    byte[] ciphertext = new byte[payload.length - IV_LENGTH];
    System.arraycopy(payload, 0, iv, 0, IV_LENGTH);
    System.arraycopy(payload, IV_LENGTH, ciphertext, 0, ciphertext.length);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
    return cipher.doFinal(ciphertext);
  }

  private static final class BodyRequest extends HttpServletRequestWrapper {
    private final byte[] body;
    private final String contentType;

    BodyRequest(HttpServletRequest request, byte[] body, String contentType) {
      super(request);
      this.body = body;
      this.contentType = contentType;
    }

    @Override public String getContentType() { return contentType; }
    @Override public int getContentLength() { return body.length; }
    @Override public long getContentLengthLong() { return body.length; }
    @Override public String getHeader(String name) {
      if ("Content-Type".equalsIgnoreCase(name)) return contentType;
      if ("Content-Length".equalsIgnoreCase(name)) return String.valueOf(body.length);
      return super.getHeader(name);
    }
    @Override public Enumeration<String> getHeaders(String name) {
      if ("Content-Type".equalsIgnoreCase(name)) return Collections.enumeration(Collections.singleton(contentType));
      if ("Content-Length".equalsIgnoreCase(name)) return Collections.enumeration(Collections.singleton(String.valueOf(body.length)));
      return super.getHeaders(name);
    }
    @Override public Enumeration<String> getHeaderNames() {
      java.util.Set<String> names = new java.util.LinkedHashSet<>(Collections.list(super.getHeaderNames()));
      names.add("Content-Type");
      names.add("Content-Length");
      return Collections.enumeration(names);
    }
    @Override public ServletInputStream getInputStream() {
      ByteArrayInputStream input = new ByteArrayInputStream(body);
      return new ServletInputStream() {
        @Override public boolean isFinished() { return input.available() == 0; }
        @Override public boolean isReady() { return true; }
        @Override public void setReadListener(ReadListener listener) {
          throw new UnsupportedOperationException("Async payload reading is not supported.");
        }
        @Override public int read() { return input.read(); }
      };
    }
  }
}
