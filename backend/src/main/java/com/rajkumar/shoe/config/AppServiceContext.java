package com.rajkumar.shoe.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Locale;

@Service
public class AppServiceContext {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final boolean otpVerificationRequired;
    private final int otpLength;
    private final int otpTtlMinutes;
    private final int otpMaxAttempts;
    private final int otpLockMinutes;
    private final boolean otpDebugEnabled;
    private final String appName;
    private final String appAddress;

    public AppServiceContext(
            @Value("${app.auth.otp-required:true}") boolean otpVerificationRequired,
            @Value("${app.auth.otp-length:6}") int otpLength,
            @Value("${app.auth.otp-ttl-minutes:5}") int otpTtlMinutes,
            @Value("${app.auth.otp-max-attempts:5}") int otpMaxAttempts,
            @Value("${app.auth.otp-lock-minutes:15}") int otpLockMinutes,
            @Value("${app.auth.otp-debug:false}") boolean otpDebugEnabled,
            @Value("${app.shop.name:Raj Kumar Shoe Repairing}") String appName,
            @Value("${app.shop.address:Bistupur, Jamshedpur, Jharkhand}") String appAddress) {
        this.otpVerificationRequired = otpVerificationRequired;
        this.otpLength = Math.max(4, Math.min(otpLength, 8));
        this.otpTtlMinutes = Math.max(1, otpTtlMinutes);
        this.otpMaxAttempts = Math.max(1, otpMaxAttempts);
        this.otpLockMinutes = Math.max(1, otpLockMinutes);
        this.otpDebugEnabled = otpDebugEnabled;
        this.appName = appName;
        this.appAddress = appAddress;
    }

    public boolean isOtpVerificationRequired() {
        return otpVerificationRequired;
    }

    public boolean isOtpDebugEnabled() {
        return otpDebugEnabled;
    }

    public int getOtpLength() {
        return otpLength;
    }

    public int getOtpTtlMinutes() {
        return otpTtlMinutes;
    }

    public int getOtpMaxAttempts() {
        return otpMaxAttempts;
    }

    public int getOtpLockMinutes() {
        return otpLockMinutes;
    }

    public String getAppName() {
        return appName;
    }

    public String getAppAddress() {
        return appAddress;
    }

    public String buildOtpMessage(String purpose) {
        String cleaned = purpose == null ? "" : purpose.trim().toUpperCase(Locale.ROOT);
        return switch (cleaned) {
            case "FORGOT_PASSWORD" -> "Use the one-time password to reset your password.";
            case "REGISTER" -> "Use the one-time password to complete registration.";
            default -> "Use the one-time password to continue.";
        };
    }

    public String buildOrderDeliveredMessage(String orderNo) {
        String safeOrderNo = orderNo == null ? "" : orderNo;
        return String.format("🎉 Your order has been delivered successfully! We hope you love your refreshed footwear. Thank you for trusting %s with order %s. We would be delighted to serve you again.", appName, safeOrderNo);
    }

    public String buildOrderStatusMessage(String orderNo, String status) {
        String normalizedStatus = status == null ? "" : status.replace('_', ' ');
        return "📦 Order " + (orderNo == null ? "" : orderNo) + " is now " + normalizedStatus + ".";
    }

    public String buildFeedbackPrompt(String feedbackUrl) {
        if (feedbackUrl == null || feedbackUrl.isBlank()) {
            return "\n\nHow did we do? Sign in and leave a rating and review";
        }
        return "\n\nHow did we do? Sign in and leave a rating and review: " + feedbackUrl;
    }

    public String generateOtp() {
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            digits.append(RANDOM.nextInt(10));
        }
        return digits.toString();
    }
}
