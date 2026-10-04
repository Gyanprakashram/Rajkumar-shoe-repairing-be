package com.rajkumar.shoe.notification;

import com.rajkumar.shoe.Models.AppUser;
import com.rajkumar.shoe.common.NotificationMessages;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.MediaType;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Component
public class OrderNotificationChannels {
    private static final Logger log = LoggerFactory.getLogger(OrderNotificationChannels.class);
    private final JavaMailSender mailSender;
    private final String mailHost;
    private final String mailFrom;
    private final String adminEmail;
    private final String whatsappToken;
    private final String whatsappPhoneId;
    private final String whatsappApiVersion;
    private final String whatsappTemplate;
    private final String whatsappLanguage;
    private final String countryCode;
    private final String adminPhone;
    private final String smsAccountSid;
    private final String smsAuthToken;
    private final String smsFrom;
    private final String frontendUrl;

    public record EmailAttachment(String fileName, String contentType, byte[] data) {}

    public OrderNotificationChannels(JavaMailSender mailSender,
        @Value("${spring.mail.host:}") String mailHost,
        @Value("${app.notifications.email-from:}") String mailFrom,
        @Value("${app.notifications.email-to:}") String adminEmail,
        @Value("${app.notifications.whatsapp-token:}") String whatsappToken,
        @Value("${app.notifications.whatsapp-phone-number-id:}") String whatsappPhoneId,
        @Value("${app.notifications.whatsapp-api-version:v22.0}") String whatsappApiVersion,
        @Value("${app.notifications.whatsapp-template:order_update}") String whatsappTemplate,
        @Value("${app.notifications.whatsapp-language:en}") String whatsappLanguage,
        @Value("${app.notifications.whatsapp-country-code:91}") String countryCode,
        @Value("${app.notifications.admin-phone:}") String adminPhone,
        @Value("${app.notifications.sms-account-sid:}") String smsAccountSid,
        @Value("${app.notifications.sms-auth-token:}") String smsAuthToken,
        @Value("${app.notifications.sms-from:}") String smsFrom,
        @Value("${app.frontend-url:http://localhost:5173}") String frontendUrl) {
        this.mailSender = mailSender;
        this.mailHost = mailHost;
        this.mailFrom = mailFrom;
        this.adminEmail = adminEmail;
        this.whatsappToken = whatsappToken;
        this.whatsappPhoneId = whatsappPhoneId;
        this.whatsappApiVersion = whatsappApiVersion;
        this.whatsappTemplate = whatsappTemplate;
        this.whatsappLanguage = whatsappLanguage;
        this.countryCode = countryCode;
        this.adminPhone = adminPhone;
        this.smsAccountSid = smsAccountSid;
        this.smsAuthToken = smsAuthToken;
        this.smsFrom = smsFrom;
        this.frontendUrl = frontendUrl;
    }

    public void sendOtp(String phone, String recipientEmail, String otp, int ttlMinutes) {
        boolean sent = recipientEmail != null && !recipientEmail.isBlank()
            && emailOtp(recipientEmail, otp, ttlMinutes);
        if (!sent && phone != null && !phone.isBlank()) {
            sent = sms(phone, String.format(NotificationMessages.OTP_MESSAGE, otp, ttlMinutes));
        }
        if (!sent) {
            throw new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE,
                "OTP delivery is not available. Configure SMTP for email or Twilio SMS as the phone fallback.");
        }
    }

    private boolean emailOtp(String recipient, String otp, int ttlMinutes) {
        if (mailHost == null || mailHost.isBlank() || mailFrom == null || mailFrom.isBlank()) return false;
        try {
            MimeMessage mail = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mail, true, "UTF-8");
            helper.setFrom(mailFrom);
            helper.setTo(recipient);
            helper.setSubject(NotificationMessages.OTP_SUBJECT);
            helper.setText(String.format(NotificationMessages.OTP_MESSAGE, otp, ttlMinutes),
                otpEmailHtml(otp, ttlMinutes));
            mailSender.send(mail);
            return true;
        } catch (MessagingException | MailException ex) {
            log.warn("Could not send OTP email; check SMTP configuration. exception={}", ex.getClass().getName());
            return false;
        }
    }

    private String otpEmailHtml(String otp, int ttlMinutes) {
        String code = escapeHtml(otp);
        String expiry = escapeHtml(String.format(NotificationMessages.OTP_EMAIL_EXPIRES, ttlMinutes));
        return """
            <!doctype html><html><body style="margin:0;padding:24px 12px;background:#f4f1ec;font-family:Arial,Helvetica,sans-serif;color:#302319">
            <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#fff;border:1px solid #e7dacc;border-radius:16px;overflow:hidden">
            <tr><td style="padding:26px 30px;background:linear-gradient(135deg,#f8f4ee,#fff0dd)"><div style="font-size:12px;text-transform:uppercase;letter-spacing:1.1px;color:#8f5a18;font-weight:bold">Raj Kumar Shoe Repairing</div><h2 style="margin:12px 0 0;color:#191919;font-size:24px">%s</h2></td></tr>
            <tr><td style="padding:28px 30px;text-align:center"><div style="font-size:14px;color:#62584f">Enter this code to continue</div><div style="display:inline-block;margin:18px 0;padding:14px 24px;border:1px solid #e7dacc;border-radius:12px;background:#fbf8f3;color:#302319;font-size:32px;font-weight:bold;letter-spacing:8px">%s</div><p style="font-size:14px;line-height:1.6;color:#62584f">%s</p></td></tr>
            <tr><td style="padding:15px 30px;background:#f7faf7;font-size:12px;color:#718078;text-align:center">If you did not request this code, you can safely ignore this email.</td></tr>
            </table></body></html>
            """.formatted(NotificationMessages.OTP_EMAIL_GREETING, code, expiry);
    }

    @Async("notificationExecutor")
    public void admin(String message) {
        admin(message, List.of());
    }

    @Async("notificationExecutor")
    public void admin(String message, List<EmailAttachment> attachments) {
        String subject = message.startsWith("New ") ? "A new customer booking needs your review" : NotificationMessages.SHOP_NAME + " · booking update";
        email(adminEmail, subject, message, attachments);
        whatsapp(adminPhone, message);
        sms(adminPhone, message);
    }

    @Async("notificationExecutor")
    public void customer(AppUser customer, String message) {
        if (customer == null) return;
        String subject = message.contains("delivered successfully")
            ? NotificationMessages.ORDER_DELIVERED_SUBJECT
            : message.startsWith("🎉 Order received")
            ? NotificationMessages.ORDER_RECEIVED_SUBJECT
            : message.contains("reviewed and approved") ? NotificationMessages.ORDER_APPROVED_SUBJECT : NotificationMessages.SHOP_NAME + " · order update";
        sendToCustomer(customer, subject, message);
    }

    @Async("notificationExecutor")
    public void customerDelivered(AppUser customer, String message, Long orderId) {
        if (customer == null) return;
        String baseUrl = frontendUrl.replaceAll("/+$", "");
        String feedbackUrl = baseUrl + "/?tab=feedback&orderId=" + orderId;
        sendToCustomer(customer, NotificationMessages.ORDER_DELIVERED_SUBJECT,
            message + String.format(NotificationMessages.ORDER_DELIVERED_FEEDBACK_SUFFIX, feedbackUrl), feedbackUrl);
    }

    @Async("notificationExecutor")
    public void customerWelcome(AppUser customer) {
        if (customer == null) return;
        sendToCustomer(customer, NotificationMessages.WELCOME_SUBJECT,
            String.format(NotificationMessages.CUSTOMER_WELCOME_MESSAGE, customer.name));
    }

    @Async("notificationExecutor")
    public void customerQuote(AppUser customer, String message) {
        if (customer == null) return;
        String contact = adminPhone == null || adminPhone.isBlank() ? "" : "\n\nNeed to ask a question? Continue with the shop on WhatsApp: https://wa.me/"
            + normalizePhone(adminPhone) + "?text=" + java.net.URLEncoder.encode(NotificationMessages.QUOTE_CONTACT_MESSAGE, StandardCharsets.UTF_8);
        sendToCustomer(customer, NotificationMessages.QUOTE_SUBJECT, message + contact);
    }

    private void sendToCustomer(AppUser customer, String subject, String message) {
        email(customer.email, subject, message, List.of());
        whatsapp(customer.phone, message);
        sms(customer.phone, message);
    }

    private void sendToCustomer(AppUser customer, String subject, String message, String feedbackUrl) {
        email(customer.email, subject, message, List.of(), feedbackUrl);
        whatsapp(customer.phone, message);
        sms(customer.phone, message);
    }

    private boolean email(String recipient, String subject, String message, List<EmailAttachment> attachments) {
        return email(recipient, subject, message, attachments, null);
    }

    private boolean email(String recipient, String subject, String message, List<EmailAttachment> attachments, String feedbackUrl) {
        if (mailHost == null || mailHost.isBlank() || mailFrom == null || mailFrom.isBlank() || recipient == null || recipient.isBlank()) return false;
        try {
            MimeMessage mail = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mail, true, "UTF-8");
            helper.setFrom(mailFrom);
            helper.setTo(recipient);
            helper.setSubject(subject);
            helper.setText(message, htmlEmail(subject, message, feedbackUrl));
            for (EmailAttachment attachment : attachments) {
                helper.addAttachment(attachment.fileName(), new ByteArrayResource(attachment.data()), attachment.contentType());
            }
            mailSender.send(mail);
            return true;
        } catch (MessagingException | MailException ex) {
            log.warn("Could not send order email; check SMTP configuration. exception={}", ex.getClass().getName());
            return false;
        }
    }

    private String htmlEmail(String subject, String message, String feedbackUrl) {
        String safeSubject = escapeHtml(subject);
        String displayMessage = feedbackUrl == null ? message : message.replace(feedbackUrl, "").stripTrailing();
        String safeMessage = escapeHtml(displayMessage).replace("\n", "<br>");
        if (message.contains("delivered successfully")) {
            return deliveredEmail(safeSubject, safeMessage, feedbackUrl);
        }
        String accent = subject.startsWith("We received") ? "#167448" : subject.startsWith("Your order has been reviewed") ? "#167448" : "#9a541e";
        return """
            <!doctype html><html><body style="margin:0;padding:24px 12px;background:#f4f1ec;font-family:Arial,Helvetica,sans-serif;color:#302319">
            <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #e7dacc;border-radius:16px;overflow:hidden">
            <tr><td style="padding:26px 30px;background:linear-gradient(135deg,#f8f4ee,#fff0dd)"><div style="font-size:12px;text-transform:uppercase;letter-spacing:1.1px;color:#8f5a18;font-weight:bold">Raj Kumar Shoe Repairing</div><h2 style="margin:12px 0 0;color:#191919;font-size:24px">%s</h2></td></tr>
            <tr><td style="padding:24px 30px"><div style="font-size:16px;line-height:1.7;color:#2f2b26">%s</div></td></tr>
            <tr><td style="padding:0 30px 24px"><div style="display:inline-block;padding:10px 18px;border-radius:999px;background:%s;color:#fff;font-weight:bold">Thank you for choosing us</div></td></tr>
            <tr><td style="padding:15px 30px;background:#f7faf7;font-size:12px;color:#718078;text-align:center">Raj Kumar Shoe Repairing · Bistupur, Jamshedpur · Serving you since 1984</td></tr>
            </table></body></html>
            """.formatted(safeSubject, safeMessage, accent);
    }

    private String deliveredEmail(String subject, String message, String feedbackUrl) {
        String cta = feedbackUrl == null ? "" : "<p style=\"margin:18px 0 0\"><a href=\"" + feedbackUrl + "\" style=\"display:inline-block;padding:12px 18px;border-radius:999px;background:#167448;color:#fff;text-decoration:none;font-weight:bold\">Leave a review</a></p>";
        return """
            <!doctype html><html><body style="margin:0;padding:24px 12px;background:#f4f1ec;font-family:Arial,Helvetica,sans-serif;color:#302319">
            <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #dfeadf;border-radius:16px;overflow:hidden">
            <tr><td style="padding:26px 30px;background:linear-gradient(135deg,#eef9f0,#f6fbf8)"><div style="font-size:12px;text-transform:uppercase;letter-spacing:1.1px;color:#2f6d4b;font-weight:bold">Raj Kumar Shoe Repairing</div><h2 style="margin:12px 0 0;color:#191919;font-size:24px">%s</h2></td></tr>
            <tr><td style="padding:24px 30px"><div style="font-size:16px;line-height:1.7;color:#2f2b26">%s</div>%s</td></tr>
            <tr><td style="padding:15px 30px;background:#f7faf7;font-size:12px;color:#718078;text-align:center">Raj Kumar Shoe Repairing · Bistupur, Jamshedpur · Serving you since 1984</td></tr>
            </table></body></html>
            """.formatted(subject, message, cta);
    }

    private String escapeHtml(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }

    private void whatsapp(String target, String message) {
        if (target == null || target.isBlank() || whatsappToken.isBlank() || whatsappPhoneId.isBlank()) return;
        try {
            String phone = normalizePhone(target);
            if (phone == null || phone.isBlank()) return;
            String endpoint = "https://graph.facebook.com/" + whatsappApiVersion + "/" + whatsappPhoneId + "/messages";
            RestClient client = RestClient.builder().baseUrl(endpoint).defaultHeader("Authorization", "Bearer " + whatsappToken).build();
            LinkedMultiValueMap<String, String> payload = new LinkedMultiValueMap<>();
            payload.add("messaging_product", "whatsapp");
            payload.add("to", phone);
            payload.add("type", "text");
            payload.add("text", message);
            client.post()
                .contentType(MediaType.APPLICATION_JSON)
                .body(payload)
                .retrieve()
                .toBodilessEntity();
        } catch (RestClientException ex) {
            log.warn("Could not send WhatsApp message to {}. exception={}", target, ex.getMessage());
        }
    }

    private boolean sms(String target, String message) {
        if (target == null || target.isBlank() || smsAccountSid == null || smsAccountSid.isBlank()
            || smsAuthToken == null || smsAuthToken.isBlank() || smsFrom == null || smsFrom.isBlank()) return false;
        String phone = normalizePhone(target);
        if (phone == null || phone.isBlank()) return false;
        String body = java.net.URLEncoder.encode(message, StandardCharsets.UTF_8);
        String uri = "https://api.twilio.com/2010-04-01/Accounts/" + smsAccountSid + "/Messages.json";
        try {
            RestClient client = RestClient.builder().baseUrl(uri)
                .defaultHeaders(headers -> headers.setBasicAuth(smsAccountSid, smsAuthToken))
                .build();
            LinkedMultiValueMap<String, String> payload = new LinkedMultiValueMap<>();
            payload.add("From", smsFrom);
            payload.add("To", "+" + countryCode + phone);
            payload.add("Body", message);
            client.post().contentType(MediaType.APPLICATION_FORM_URLENCODED).body(payload).retrieve().toBodilessEntity();
            return true;
        } catch (RestClientException ex) {
            log.warn("Could not send SMS to {}. exception={}", target, ex.getMessage());
            return false;
        }
    }

    private static String normalizePhone(String value) {
        if (value == null) return null;
        String digits = value.replaceAll("\\D+", "");
        return digits.length() == 10 ? digits : digits;
    }
}
