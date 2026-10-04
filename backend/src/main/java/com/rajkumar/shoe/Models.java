package com.rajkumar.shoe;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.*;

/** Entities + repositories. Amounts are whole rupees. */
public class Models {
  @Entity @Table(name="users") public static class AppUser {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    public String name, role="USER";
    @Column(unique=true) public String phone;
    @Column(unique=true) public String email;
    @JsonIgnore public String passwordHash; }

  @Entity @Table(name="otp_verifications", indexes={@Index(name="idx_otp_target_purpose", columnList="target_value,purpose")})
  public static class OtpVerification {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    @Column(name="target_value", nullable=false, length=320) public String targetValue;
    @Column(name="purpose", nullable=false, length=40) public String purpose;
    @Column(name="otp_hash", nullable=false, length=128) public String otpHash;
    @Column(name="created_at", nullable=false, columnDefinition="TIMESTAMP") public LocalDateTime createdAt;
    @Column(name="expires_at", nullable=false, columnDefinition="TIMESTAMP") public LocalDateTime expiresAt;
    @Column(name="attempt_count", nullable=false) public int attempts;
    @Column(name="max_attempts") public Integer maxAttempts;
    @Column(name="locked_until", columnDefinition="TIMESTAMP") public LocalDateTime lockedUntil;
    @Column(name="user_id") public Long userId;
  }

  @Entity @Table(name="products") public static class Product {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    public String name, category, emoji;
    @Column(length=500) public String description;
    @Column(name="image_content_type") public String imageContentType;
    @Lob @Column(name="image_data",columnDefinition="BLOB") @JsonIgnore public byte[] imageData;
    public int price, mrp, stock; public boolean active=true; }

  /** type: MATERIAL|REPAIR|CUSTOM|BULK_REPAIR · paymentMode: ONLINE|PAY_ON_DELIVERY|QUOTE
   *  status: PLACED→CONFIRMED→IN_PROGRESS→READY→OUT_FOR_DELIVERY→DELIVERED | DECLINED
   *  paymentStatus: PENDING|AWAITING_VERIFICATION|PAID|REFUND_PENDING|REFUNDED|NONE */
  @Entity @Table(name="orders") public static class Booking {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    public String orderNo, userName, userPhone, userEmail, type, paymentMode, paymentStatus, status, utr;
    public Long userId;
    @Column(length=1000) public String description;
    @Column(length=500) public String address, adminNote;
    @Column(name="footwear_type",length=255) public String footwearType;
    @Column(name="estimated_quantity") public Integer estimatedQuantity;
    public int total, advance, paidAmount; public boolean pickup; @Column(columnDefinition="TIMESTAMP") public LocalDateTime createdAt; }

  @Entity @Table(name="order_images") public static class OrderImage {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    public Long orderId;
    public String fileName, contentType;
    @Lob @Column(columnDefinition="BLOB") @JsonIgnore public byte[] imageData;
  }

  @Entity @Table(name="repair_order_images") public static class RepairOrderImage {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    public Long orderId;
    public String fileName, contentType;
    @Lob @Column(name="image_base64", columnDefinition="CLOB") @JsonIgnore public String imageBase64;
  }

  @Entity @Table(name="notifications") public static class Notification {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    public Long userId; public boolean forAdmin, seen;
    @Column(length=500) public String message; public String orderNo; @Column(columnDefinition="TIMESTAMP") public LocalDateTime createdAt; }

  @Entity @Table(name="user_sessions") public static class UserSession {
    @Id @Column(length=36) public String id;
    @Column(name="user_id",nullable=false) public Long userId;
    @Column(name="refresh_token_hash",nullable=false,unique=true,length=64) public String refreshTokenHash;
    @Column(name="last_activity",nullable=false,columnDefinition="TIMESTAMP") public LocalDateTime lastActivity;
  }

  @Entity @Table(name="settings") public static class Setting {
    @Id public String skey; @Column(columnDefinition="CLOB") public String svalue; }

  @Entity @Table(name="rk_staticdata") public static class StaticDataEntry {
    @Id @Column(name="data_key",length=100) public String key;
    @Lob @Column(name="data_value",columnDefinition="CLOB") public String value;
  }

  @Entity @Table(name="customer_feedback",uniqueConstraints=@UniqueConstraint(name="uk_feedback_order",columnNames="order_id"))
  public static class CustomerFeedback {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
    @Column(name="order_id",nullable=false) public Long orderId;
    @Column(name="user_id",nullable=false) public Long userId;
    @Column(name="order_no",nullable=false,length=50) public String orderNo;
    @Column(name="customer_name",nullable=false,length=100) public String customerName;
    @Column(nullable=false) public int rating;
    @Column(nullable=false,length=1000) public String review;
    @Column(name="created_at",nullable=false,columnDefinition="TIMESTAMP") public LocalDateTime createdAt;
  }

  public interface Users extends JpaRepository<AppUser,Long> {
    Optional<AppUser> findByPhone(String p);
    Optional<AppUser> findByEmail(String email);
    Optional<AppUser> findByEmailIgnoreCase(String email);
  }

  public interface OtpVerifications extends JpaRepository<OtpVerification,Long> {
    Optional<OtpVerification> findByTargetValueAndPurpose(String targetValue, String purpose);
    Optional<OtpVerification> findFirstByTargetValueAndLockedUntilAfter(String targetValue, LocalDateTime now);
  }
  public interface Products extends JpaRepository<Product,Long> {
    List<Product> findByActiveTrueOrderByIdDesc();
    List<Product> findAllByOrderByIdDesc();
  }
  public interface Bookings extends JpaRepository<Booking,Long> { List<Booking> findByUserIdOrderByIdDesc(Long u); List<Booking> findAllByOrderByIdDesc();  }
  public interface OrderImages extends JpaRepository<OrderImage,Long> { List<OrderImage> findByOrderIdOrderByIdAsc(Long orderId); Optional<OrderImage> findByIdAndOrderId(Long id,Long orderId); }
  public interface RepairOrderImages extends JpaRepository<RepairOrderImage,Long> { List<RepairOrderImage> findByOrderIdOrderByIdAsc(Long orderId); }
  public interface Notes extends JpaRepository<Notification,Long> {
    List<Notification> findByUserIdOrderByIdDesc(Long u);
    List<Notification> findByForAdminTrueOrderByIdDesc();
    long deleteByUserId(Long userId);
    long deleteByForAdminTrue();
  }
  public interface Sessions extends JpaRepository<UserSession,String> {
    Optional<UserSession> findByRefreshTokenHash(String refreshTokenHash);
    long deleteByRefreshTokenHash(String refreshTokenHash);
  }
  public interface Settings extends JpaRepository<Setting,String> {}
  public interface StaticData extends JpaRepository<StaticDataEntry,String> {}
  public interface Feedback extends JpaRepository<CustomerFeedback,Long> {
    boolean existsByOrderId(Long orderId);
    Optional<CustomerFeedback> findByOrderId(Long orderId);
    List<CustomerFeedback> findAllByOrderByCreatedAtDesc();
  }
}
