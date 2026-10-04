package com.rajkumar.shoe.auth;

import com.rajkumar.shoe.Models.OtpVerification;
import com.rajkumar.shoe.Models.OtpVerifications;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

@Service
public class OtpProtectionService {
    private final OtpVerifications verifications;

    public OtpProtectionService(OtpVerifications verifications) {
        this.verifications = verifications;
    }

    public void ensureUnlocked(String target, int lockMinutes) {
        verifications.findFirstByTargetValueAndLockedUntilAfter(target, LocalDateTime.now())
            .ifPresent(verification -> throwLocked(lockMinutes));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public OtpVerification recordFailedAttempt(String target, String purpose, int maxAttempts, int lockMinutes) {
        OtpVerification verification = verifications.findByTargetValueAndPurpose(target, purpose)
            .orElseThrow(() -> new IllegalStateException("OTP verification record disappeared during attempt tracking."));
        verification.attempts++;
        verification.maxAttempts = maxAttempts;
        if (verification.attempts >= maxAttempts) {
            verification.lockedUntil = LocalDateTime.now().plusMinutes(lockMinutes);
        }
        return verifications.save(verification);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void associateUser(String target, String purpose, Long userId) {
        verifications.findByTargetValueAndPurpose(target, purpose).ifPresent(verification -> {
            verification.userId = userId;
            verifications.save(verification);
        });
    }

    private static void throwLocked(int lockMinutes) {
        throw new ResponseStatusException(HttpStatus.LOCKED,
            "Too many incorrect OTP attempts. This account is locked for " + lockMinutes + " minutes.");
    }
}
