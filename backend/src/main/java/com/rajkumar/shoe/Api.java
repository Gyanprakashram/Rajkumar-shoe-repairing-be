package com.rajkumar.shoe;
import com.rajkumar.shoe.Models.*;
import com.rajkumar.shoe.auth.OtpProtectionService;
import com.rajkumar.shoe.common.NotificationMessages;
import com.rajkumar.shoe.config.StaticDataConfig;
import com.rajkumar.shoe.notification.OrderNotificationChannels;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.MediaType;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.time.LocalDateTime;
import java.util.*;

public class Api {
  static ResponseStatusException bad(String m){ return new ResponseStatusException(HttpStatus.BAD_REQUEST,m); }
  static ResponseStatusException nf(){ return new ResponseStatusException(HttpStatus.NOT_FOUND,"Not found"); }
  static String cancellationAdminMessage(Booking order,String reason,String fallbackReason,String countryCode){
    String phone=order.userPhone==null?"":order.userPhone.replaceAll("\\D","");
    if(phone.length()==10)phone=(countryCode==null?"":countryCode.replaceAll("\\D",""))+phone;
    String product=order.description==null?order.type:order.description;
    String effectiveReason=reason==null||reason.isBlank()?fallbackReason:reason;
    String customerMessage=String.format(NotificationMessages.ORDER_CANCELLATION_WHATSAPP_TEXT,
      order.userName,order.type==null?"order":order.type.replace('_',' '),order.orderNo,product,effectiveReason);
    String contactLink=phone.isBlank()?"Unavailable: customer phone number is missing."
      :"https://wa.me/"+phone+"?text="+java.net.URLEncoder.encode(customerMessage,java.nio.charset.StandardCharsets.UTF_8);
    return String.format(NotificationMessages.ORDER_CANCELLATION_CONTACT_MESSAGE,order.orderNo,
      order.userName,product,effectiveReason,contactLink);
  }
  static boolean validImage(MultipartFile image){
    try{
      byte[] b=image.getBytes(); String type=image.getContentType();
      if("image/jpeg".equalsIgnoreCase(type)) return b.length>=3&&(b[0]&255)==255&&(b[1]&255)==216&&(b[2]&255)==255;
      if("image/png".equalsIgnoreCase(type)) return b.length>=8&&(b[0]&255)==137&&b[1]==80&&b[2]==78&&b[3]==71&&b[4]==13&&b[5]==10&&b[6]==26&&b[7]==10;
      if("image/webp".equalsIgnoreCase(type)) return b.length>=12&&new String(b,0,4,java.nio.charset.StandardCharsets.US_ASCII).equals("RIFF")&&new String(b,8,4,java.nio.charset.StandardCharsets.US_ASCII).equals("WEBP");
      return false;
    }catch(IOException ex){ return false; }
  }
  static boolean isAdmin(Authentication a){ return a.getAuthorities().stream().anyMatch(g->g.getAuthority().equals("ROLE_ADMIN")); }
  /** Server-side price list (clients can't tamper with prices). */
  static final Map<String,Integer> SV=Map.of("Polish & clean",80,"Stitching",150,"Sticking / glue",200,"Sole replacement",350,
    "Leather jacket polish",450,"Leather belt (made to order)",250,"Wedding shoes",2500,"Orthopedic / handicapped shoes",1800,
    "Animal-design shoes",2000,"Own design",1500);

  /** Stores in-app notifications. Hook SMS / WhatsApp / FCM / Kafka producer in save(). */
  @Service public static class Notify {
    final Notes notes; final Users users; final OrderNotificationChannels channels;
    public Notify(Notes n,Users users,OrderNotificationChannels channels){ notes=n; this.users=users; this.channels=channels; }
    public void admin(String message,String no){ save(null,true,message,no); afterCommit(()->channels.admin(message)); }
    public void admin(String message,String no,List<OrderNotificationChannels.EmailAttachment> attachments){
      save(null,true,message,no); afterCommit(()->channels.admin(message,attachments));
    }
    public void user(Long id,String message,String no){
      save(id,false,message,no);
      users.findById(id).ifPresent(customer->afterCommit(()->channels.customer(customer,message)));
    }
    public void delivered(Long id,String message,String no,Long orderId){
      save(id,false,message,no);
      users.findById(id).ifPresent(customer->afterCommit(()->channels.customerDelivered(customer,message,orderId)));
    }
    public void quoteCustomer(Long id,String message,String no){
      save(id,false,message,no);
      users.findById(id).ifPresent(customer->afterCommit(()->channels.customerQuote(customer,message)));
    }
    private void afterCommit(Runnable dispatch){
      if(!TransactionSynchronizationManager.isSynchronizationActive()){ dispatch.run(); return; }
      TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
        @Override public void afterCommit(){ dispatch.run(); }
      });
    }
    void save(Long u,boolean a,String m,String no){ Notification n=new Notification(); n.userId=u; n.forAdmin=a; n.message=m.length()>500?m.substring(0,500):m; n.orderNo=no; n.createdAt=LocalDateTime.now(); notes.save(n); }
  }
  @RestController @RequestMapping("/api/auth") public static class Auth {
    final Users users; final Sessions sessions; final PasswordEncoder enc; final Sec.Jwt jwt;
    final OrderNotificationChannels channels; final long idleTimeoutMs; final OtpVerifications otpVerifications; final OtpProtectionService otpProtection; final com.rajkumar.shoe.config.AppServiceContext appServiceContext;
    static final SecureRandom RANDOM=new SecureRandom();
    public Auth(Users u,Sessions sessions,PasswordEncoder e,Sec.Jwt j,OrderNotificationChannels channels,
        OtpVerifications otpVerifications, OtpProtectionService otpProtection,
        com.rajkumar.shoe.config.AppServiceContext appServiceContext,
        @Value("${app.session-idle-timeout-ms}") long idleTimeoutMs){
      users=u; this.sessions=sessions; enc=e; jwt=j; this.channels=channels; this.idleTimeoutMs=idleTimeoutMs;
      this.otpVerifications=otpVerifications; this.otpProtection=otpProtection; this.appServiceContext=appServiceContext;
    }
    public record Reg(String name,String phone,String password,String email,String otp){}
    public record Log(String identifier,String phone,String email,String password){}
    public record Refresh(String refreshToken){}
    public record OtpRequest(String phone,String email,String identifier,String purpose){}
    public record OtpVerify(String phone,String email,String identifier,String otp,String purpose){}
    public record ForgotPassword(String identifier,String otp,String password){}

    @PostMapping("/request-otp") @Transactional public Map<String,Object> requestOtp(@RequestBody OtpRequest request){
      if(request==null) throw bad("Provide a phone number or email to request OTP.");
      String purpose=(request.purpose()==null?"REGISTER":request.purpose().trim().toUpperCase(Locale.ROOT));
      if(!Set.of("REGISTER","FORGOT_PASSWORD").contains(purpose)) throw bad("OTP purpose must be REGISTER or FORGOT_PASSWORD.");
      if(!appServiceContext.isOtpVerificationRequired())
        return Map.of("message","OTP verification is disabled in configuration.");
      String target=normalizeIdentifier(request.identifier(), request.phone(), request.email());
      if(target==null||target.isBlank()) throw bad("Enter a valid phone number or email address.");
      AppUser otpUser=null;
      if("REGISTER".equals(purpose)){
        String phone=normalizePhone(request.phone());
        if(phone==null||!phone.matches("\\d{10}")) throw bad("Enter a valid 10-digit phone number for registration.");
        String email=normalizeEmail(request.email());
        if(email==null) throw bad("A valid Gmail or email address is required to create an account.");
        if(users.findByPhone(phone).isPresent()||users.findByEmailIgnoreCase(email).isPresent())
          throw new ResponseStatusException(HttpStatus.CONFLICT,"An account with this phone number or email already exists. Please log in or reset your password.");
        target=phone;
      } else {
        otpUser=findAccountByIdentifier(target).orElseThrow(()->bad("No account was found for this phone or email."));
        if(otpUser.phone==null||otpUser.phone.isBlank()) throw bad("Phone number is missing for this account.");
        target=normalizePhone(otpUser.phone);
      }
      otpProtection.ensureUnlocked(target, appServiceContext.getOtpLockMinutes());
      String otp=appServiceContext.generateOtp();
      OtpVerification verification=otpVerifications.findByTargetValueAndPurpose(target,purpose).orElse(new OtpVerification());
      verification.targetValue=target;
      verification.purpose=purpose;
      verification.otpHash=hashOtp(otp);
      verification.createdAt=LocalDateTime.now();
      verification.expiresAt=verification.createdAt.plusMinutes(appServiceContext.getOtpTtlMinutes());
      verification.attempts=0;
      verification.maxAttempts=appServiceContext.getOtpMaxAttempts();
      verification.lockedUntil=null;
      verification.userId=otpUser==null?null:otpUser.id;
      otpVerifications.save(verification);
      if(!appServiceContext.isOtpDebugEnabled()){
        String destinationEmail="REGISTER".equals(purpose)?request.email():otpUser.email;
        channels.sendOtp(target,destinationEmail,otp,appServiceContext.getOtpTtlMinutes());
      }
      Map<String,Object> response=new LinkedHashMap<>();
      response.put("message", appServiceContext.buildOtpMessage(purpose));
      if(appServiceContext.isOtpDebugEnabled()) response.put("debugOtp", otp);
      return response;
    }

    @PostMapping("/verify-otp") public Map<String,Object> verifyOtp(@RequestBody OtpVerify request){
      if(request==null) throw bad("OTP verification requires a phone, email, or identifier.");
      if(!appServiceContext.isOtpVerificationRequired()) return Map.of("verified",true,"message","OTP validation is disabled in configuration.");
      String purpose=(request.purpose()==null?"REGISTER":request.purpose().trim().toUpperCase(Locale.ROOT));
      if(!Set.of("REGISTER","FORGOT_PASSWORD").contains(purpose)) throw bad("OTP purpose must be REGISTER or FORGOT_PASSWORD.");
      String target=resolveOtpTarget(request.identifier(),request.phone(),request.email());
      if(target==null||target.isBlank()) throw bad("Enter a valid phone number or email address.");
      otpProtection.ensureUnlocked(target, appServiceContext.getOtpLockMinutes());
      OtpVerification verification=otpVerifications.findByTargetValueAndPurpose(target,purpose)
        .orElseThrow(()->bad("No OTP was requested for this account yet."));
      if(verification.expiresAt.isBefore(LocalDateTime.now())) throw bad("This OTP has expired. Request a new one.");
      int maxAttempts=verification.maxAttempts==null?appServiceContext.getOtpMaxAttempts():verification.maxAttempts;
      if(verification.attempts>=maxAttempts) throw bad("This OTP has been used too many times. Request a new one.");
      if(!verifyOtpValue(request.otp(), verification.otpHash)){
        rejectOtpAttempt(target,purpose);
      }
      verification.expiresAt=LocalDateTime.now().minusMinutes(1);
      otpVerifications.save(verification);
      return Map.of("verified",true,"message","OTP verified successfully.");
    }

    @PostMapping("/register") @Transactional public Map<String,Object> reg(@RequestBody Reg r){
      if(r==null||r.name()==null||r.name().trim().length()<2||r.name().trim().length()>100||r.phone()==null||!r.phone().matches("\\d{10}")
          ||r.password()==null||r.password().length()<6||r.password().length()>72
          ||normalizeEmail(r.email())==null)
        throw bad("Enter your name, a valid 10-digit phone, a valid Gmail or email address, and a password (6–72 characters).");
      String normalizedEmail=normalizeEmail(r.email());
      if(users.findByPhone(r.phone()).isPresent()||users.findByEmailIgnoreCase(normalizedEmail).isPresent())
        throw new ResponseStatusException(HttpStatus.CONFLICT,"An account with this phone number or email already exists. Please log in or reset your password.");
      if(appServiceContext.isOtpVerificationRequired()){
        otpProtection.ensureUnlocked(r.phone(),appServiceContext.getOtpLockMinutes());
        String otpValue=r.otp()==null?"":r.otp().trim();
        if(otpValue.isBlank()) throw bad("OTP is required to register.");
        verifyOtpValueForTarget(r.phone(), "REGISTER", otpValue);
      }
      AppUser u=new AppUser(); u.name=r.name().trim(); u.phone=r.phone().trim(); u.email=normalizedEmail; u.passwordHash=enc.encode(r.password()); u.role="USER"; users.save(u);
      if(appServiceContext.isOtpVerificationRequired()) otpProtection.associateUser(u.phone,"REGISTER",u.id);
      channels.customerWelcome(u);
      return out(u); }
    @PostMapping("/login") @Transactional public Map<String,Object> login(@RequestBody Log r){
      if(r==null||r.password()==null||r.password().isBlank())
        throw bad("Enter a valid phone number or email and password.");
      String identifier=normalizeIdentifier(r.identifier(), r.phone(), r.email());
      if(identifier==null||identifier.isBlank()) throw bad("Enter a valid phone number or email address.");
      if(normalizePhone(identifier)==null&&normalizeEmail(identifier)==null)
        throw bad("Use your registered 10-digit phone number or a valid email address to log in.");
      AppUser u=findAccountByIdentifier(identifier).orElseThrow(()->new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid phone/email or password"));
      if(appServiceContext.isOtpVerificationRequired()) otpProtection.ensureUnlocked(normalizePhone(u.phone),appServiceContext.getOtpLockMinutes());
      if(!enc.matches(r.password(),u.passwordHash)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid phone/email or password");
      return out(u); }
    @PostMapping("/forgot-password") @Transactional public Map<String,Object> forgotPassword(@RequestBody ForgotPassword request){
      if(request==null||request.identifier()==null||request.identifier().isBlank()||request.password()==null||request.password().length()<6||request.password().length()>72)
        throw bad("Provide a valid phone/email, OTP, and a new password (6–72 characters).");
      AppUser user=findAccountByIdentifier(request.identifier()).orElseThrow(()->bad("No account was found for this phone or email."));
      String target=normalizePhone(user.phone);
      if(appServiceContext.isOtpVerificationRequired()){
        otpProtection.ensureUnlocked(target,appServiceContext.getOtpLockMinutes());
        String otpValue=request.otp()==null?"":request.otp().trim();
        if(otpValue.isBlank()) throw bad("OTP is required to reset your password.");
        verifyOtpValueForTarget(target, "FORGOT_PASSWORD", otpValue);
      }
      user.passwordHash=enc.encode(request.password());
      users.save(user);
      Map<String,Object> response=new LinkedHashMap<>(out(user));
      response.put("message","Password updated successfully.");
      return response;
    }
    @PostMapping("/refresh") public Map<String,Object> refresh(@RequestBody Refresh request){
      String raw=request==null?null:request.refreshToken();
      if(raw==null||raw.length()>100) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Session expired. Please sign in again.");
      UserSession session=sessions.findByRefreshTokenHash(hashToken(raw))
        .orElseThrow(()->new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Session expired. Please sign in again."));
      LocalDateTime now=LocalDateTime.now();
      if(session.lastActivity==null||java.time.Duration.between(session.lastActivity,now).toMillis()>idleTimeoutMs){
        sessions.delete(session);
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Session expired after inactivity. Please sign in again.");
      }
      AppUser user=users.findById(session.userId).orElseThrow(()->new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Account is unavailable."));
      String replacement=refreshToken();
      session.refreshTokenHash=hashToken(replacement);
      session.lastActivity=now;
      sessions.save(session);
      return Map.of("token",jwt.make(user,session.id),"refreshToken",replacement);
    }
    @PostMapping("/logout") @Transactional public void logout(@RequestBody(required=false) Refresh request){
      String raw=request==null?null:request.refreshToken();
      if(raw!=null&&!raw.isBlank()&&raw.length()<=100) sessions.deleteByRefreshTokenHash(hashToken(raw));
    }
    Map<String,Object> out(AppUser user){
      String sessionId=UUID.randomUUID().toString(),refresh=refreshToken();
      UserSession session=new UserSession(); session.id=sessionId; session.userId=user.id;
      session.refreshTokenHash=hashToken(refresh); session.lastActivity=LocalDateTime.now(); sessions.save(session);
      return Map.of("token",jwt.make(user,sessionId),"refreshToken",refresh,"user",user);
    }
    private Optional<AppUser> findAccountByIdentifier(String identifier){
      String normalized=normalizeIdentifier(identifier,null,null);
      if(normalized==null||normalized.isBlank()) return Optional.empty();
      if(normalized.contains("@")) return users.findByEmailIgnoreCase(normalized);
      String phone=normalizePhone(normalized);
      return phone==null||phone.isBlank()?Optional.empty():users.findByPhone(phone);
    }
    private static String normalizePhone(String raw){
      if(raw==null) return null;
      String digits=raw.replaceAll("\\D+","");
      return digits.length()==10?digits:null;
    }
    private static String normalizeIdentifier(String identifier,String phone,String email){
      if(identifier!=null&&!identifier.isBlank()){ String value=identifier.trim(); if(value.contains("@")) return value.toLowerCase(Locale.ROOT); String maybePhone=normalizePhone(value); return maybePhone!=null?maybePhone:value; }
      if(email!=null&&!email.isBlank()) return email.trim().toLowerCase(Locale.ROOT);
      if(phone!=null&&!phone.isBlank()) return normalizePhone(phone);
      return null;
    }
    private static String normalizeEmail(String email){
      if(email==null||email.isBlank())return null;
      String normalized=email.trim().toLowerCase(Locale.ROOT);
      return normalized.length()<=255&&normalized.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")?normalized:null;
    }
    private String resolveOtpTarget(String identifier,String phone,String email){
      String normalized=normalizeIdentifier(identifier,phone,email);
      if(normalized==null||normalized.isBlank()) return null;
      AppUser user=findAccountByIdentifier(normalized).orElse(null);
      return user==null?normalizePhone(normalized):normalizePhone(user.phone);
    }
    private void rejectOtpAttempt(String target,String purpose){
      OtpVerification attempt=otpProtection.recordFailedAttempt(
        target,purpose,appServiceContext.getOtpMaxAttempts(),appServiceContext.getOtpLockMinutes());
      if(attempt.lockedUntil!=null&&attempt.lockedUntil.isAfter(LocalDateTime.now()))
        throw new ResponseStatusException(HttpStatus.LOCKED,
          "Too many incorrect OTP attempts. This account is locked for "+appServiceContext.getOtpLockMinutes()+" minutes.");
      int remaining=Math.max(0,appServiceContext.getOtpMaxAttempts()-attempt.attempts);
      throw bad("The OTP is incorrect. "+remaining+" attempt(s) remaining.");
    }
    private void verifyOtpValueForTarget(String target, String purpose, String otpValue){
      if(!appServiceContext.isOtpVerificationRequired()) return;
      String normalizedTarget=resolveOtpTarget(target,null,null);
      if(normalizedTarget==null||normalizedTarget.isBlank()) throw bad("A valid phone number or email is required for OTP validation.");
      otpProtection.ensureUnlocked(normalizedTarget,appServiceContext.getOtpLockMinutes());
      OtpVerification verification=otpVerifications.findByTargetValueAndPurpose(normalizedTarget, purpose)
        .orElseThrow(()->bad("No OTP was requested for this account yet."));
      if(verification.expiresAt.isBefore(LocalDateTime.now())) throw bad("This OTP has expired. Request a new one.");
      int maxAttempts=verification.maxAttempts==null?appServiceContext.getOtpMaxAttempts():verification.maxAttempts;
      if(verification.attempts>=maxAttempts) throw bad("This OTP has been used too many times. Request a new one.");
      if(!verifyOtpValue(otpValue, verification.otpHash)){
        rejectOtpAttempt(normalizedTarget,purpose);
      }
      verification.expiresAt=LocalDateTime.now().minusMinutes(1);
      otpVerifications.save(verification);
    }
    private boolean verifyOtpValue(String input, String storedHash){
      if(input==null||input.isBlank()) return false;
      String normalized=input.trim();
      if(!appServiceContext.isOtpVerificationRequired()) return true;
      return hashOtp(normalized).equals(storedHash);
    }
    private static String hashOtp(String raw){
      try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}
      catch(java.security.NoSuchAlgorithmException ex){throw new IllegalStateException("SHA-256 is unavailable",ex);}
    }
    private static String refreshToken(){
      byte[] bytes=new byte[32]; RANDOM.nextBytes(bytes);
      return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    private static String hashToken(String raw){
      try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}
      catch(java.security.NoSuchAlgorithmException ex){throw new IllegalStateException("SHA-256 is unavailable",ex);}
    }
  }

  @RestController public static class Prods {
    final Products p; final ObjectMapper mapper;
    public Prods(Products p,ObjectMapper mapper){ this.p=p; this.mapper=mapper; }
    static final Set<String> PRODUCT_CATEGORIES=Set.of("Soles","Adhesives","Heels","Insoles","Polish","Leather","Tools","Other");
    public record VariantInput(String id,Map<String,String> options,int price,int mrp,int stock){}
    public record VariantView(String id,Map<String,String> options,int price,int mrp,int stock){}
    public record ProductInput(String name,String category,String emoji,String description,int price,int mrp,int stock,boolean active,List<VariantInput> variants){}
    public record ProductView(Long id,String name,String category,String emoji,String description,int price,int mrp,int stock,boolean active,String imageUrl,List<VariantView> variants){}
    void validateProduct(ProductInput product){
      if(product==null||product.name()==null||product.name().trim().length()<2||product.name().trim().length()>255)throw bad("Enter a product name from 2 to 255 characters.");
      if(product.category()==null||!PRODUCT_CATEGORIES.contains(product.category()))throw bad("Choose a valid product section.");
      if(product.price()<0||product.mrp()<0||product.stock()<0)throw bad("Price, MRP, and stock cannot be negative.");
      if(product.description()!=null&&product.description().length()>500)throw bad("Product description must be 500 characters or fewer.");
      List<VariantInput> variants=product.variants()==null?List.of():product.variants();
      if(variants.size()>100)throw bad("A product can have up to 100 variants.");
      Set<String> ids=new HashSet<>(),combinations=new HashSet<>(); Set<String> optionNames=null; int variantStockTotal=0;
      for(VariantInput variant:variants){
        if(variant==null||variant.options()==null||variant.options().isEmpty()||variant.options().size()>8)
          throw bad("Each variant needs between 1 and 8 option values.");
        if(variant.price()<0||variant.mrp()<variant.price()||variant.stock()<0)
          throw bad("Each variant needs a non-negative price, MRP at least the price, and non-negative stock.");
        TreeMap<String,String> clean=new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        variant.options().forEach((key,value)->{
          if(key==null||value==null||key.trim().isEmpty()||key.trim().length()>30||value.trim().isEmpty()||value.trim().length()>80)
            throw bad("Variant option names and values must be between 1 and 80 characters.");
          clean.put(key.trim(),value.trim());
        });
        Set<String> names=clean.keySet().stream().map(name->name.toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toSet());
        if(optionNames==null)optionNames=names;
        else if(!optionNames.equals(names))throw bad("All variants for a product must use the same option names.");
        if(clean.values().stream().anyMatch(String::isBlank))throw bad("Variant options cannot be empty.");
        String combination=clean.toString().toLowerCase(Locale.ROOT);
        if(!combinations.add(combination))throw bad("Each variant combination must be unique.");
        try{variantStockTotal=Math.addExact(variantStockTotal,variant.stock());}
        catch(ArithmeticException ex){throw bad("Combined variant stock is too large.");}
        String id=variant.id();
        if(id!=null&&!id.isBlank()&&!ids.add(id))throw bad("Variant identifiers must be unique.");
      }
    }
    List<VariantView> variants(Product product){
      if(product.variantsData==null||product.variantsData.isBlank())return List.of();
      try{return mapper.readValue(product.variantsData,new TypeReference<List<VariantView>>(){});}
      catch(JsonProcessingException ex){throw new IllegalStateException("Stored product variants are invalid for product "+product.id,ex);}
    }
    void setVariants(Product product,List<VariantInput> input){
      if(input==null){product.variantsData=null;return;}
      List<VariantView> result=input.stream().map(value->new VariantView(
        value.id()==null||value.id().isBlank()?UUID.randomUUID().toString():value.id(),
        new TreeMap<>(value.options()),value.price(),value.mrp(),value.stock())).toList();
      try{product.variantsData=mapper.writeValueAsString(result);}
      catch(JsonProcessingException ex){throw new IllegalStateException("Could not store product variants.",ex);}
    }
    ProductView productView(Product product,boolean admin){
      List<VariantView> choices=variants(product);
      int price=choices.isEmpty()?product.price:choices.stream().mapToInt(VariantView::price).min().orElse(product.price);
      int mrp=choices.isEmpty()?product.mrp:choices.stream().mapToInt(VariantView::mrp).max().orElse(product.mrp);
      int stock=choices.isEmpty()?product.stock:choices.stream().mapToInt(VariantView::stock).sum();
      return new ProductView(product.id,product.name,product.category,product.emoji,product.description,
        price,mrp,stock,product.active,product.imageData==null?null:(admin?"/api/admin/products/":"/api/products/")+product.id+"/image",choices);
    }
    @GetMapping("/api/products") public List<ProductView> list(){ return p.findByActiveTrueOrderByIdDesc().stream().map(product->productView(product,false)).toList(); }
    @GetMapping("/api/admin/products") public List<ProductView> adminList(){ return p.findAllByOrderByIdDesc().stream().map(product->productView(product,true)).toList(); }
    @GetMapping("/api/products/{id}/image") public ResponseEntity<byte[]> image(@PathVariable Long id){
      Product product=p.findById(id).filter(x->x.active&&x.imageData!=null&&x.imageContentType!=null)
        .orElseThrow(Api::nf);
      return ResponseEntity.ok().contentType(MediaType.parseMediaType(product.imageContentType)).body(product.imageData);
    }
    @GetMapping("/api/admin/products/{id}/image") public ResponseEntity<byte[]> adminImage(@PathVariable Long id){
      Product product=p.findById(id).filter(x->x.imageData!=null&&x.imageContentType!=null).orElseThrow(Api::nf);
      return ResponseEntity.ok().contentType(MediaType.parseMediaType(product.imageContentType)).body(product.imageData);
    }
    @PostMapping(path="/api/admin/products",consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
    public ProductView add(@RequestPart("product") ProductInput x,@RequestPart(value="image",required=false) MultipartFile image) throws IOException {
      validateProduct(x);
      Product product=new Product();
      product.name=x.name().trim(); product.category=x.category().trim(); product.emoji=x.emoji();
      product.description=x.description(); product.price=x.price(); product.mrp=Math.max(x.mrp(),x.price());
      product.stock=x.stock(); product.active=x.active();
      setVariants(product,x.variants());
      if(image!=null&&!image.isEmpty()){
        if(image.getSize()>5L*1024*1024||!validImage(image))
          throw bad("Product image must be a valid JPG, PNG, or WebP image no larger than 5 MB.");
        product.imageData=image.getBytes();
        product.imageContentType=image.getContentType();
      }
      return productView(p.save(product),true);
    }
    void updateFields(Product o,ProductInput x){
      validateProduct(x);
      o.name=x.name().trim(); o.category=x.category().trim(); o.price=x.price(); o.mrp=Math.max(x.mrp(),x.price());
      o.emoji=x.emoji(); o.description=x.description(); o.stock=x.stock(); o.active=x.active();
      if(x.variants()!=null)setVariants(o,x.variants());
    }
    @PutMapping(path="/api/admin/products/{id}",consumes=MediaType.APPLICATION_JSON_VALUE) @Transactional
    public ProductView upd(@PathVariable Long id,@RequestBody ProductInput x){
      Product o=p.findById(id).orElseThrow(Api::nf); updateFields(o,x); return productView(p.save(o),true);
    }
    @PutMapping(path="/api/admin/products/{id}",consumes=MediaType.MULTIPART_FORM_DATA_VALUE) @Transactional
    public ProductView updWithImage(@PathVariable Long id,@RequestPart("product") ProductInput x,
        @RequestPart(value="image",required=false) MultipartFile image,
        @RequestParam(value="removeImage",defaultValue="false") boolean removeImage) throws IOException {
      Product o=p.findById(id).orElseThrow(Api::nf);
      updateFields(o,x);
      if(image!=null&&!image.isEmpty()){
        if(image.getSize()>5L*1024*1024||!validImage(image))
          throw bad("Product image must be a valid JPG, PNG, or WebP image no larger than 5 MB.");
        o.imageData=image.getBytes(); o.imageContentType=image.getContentType();
      }else if(removeImage){ o.imageData=null; o.imageContentType=null; }
      return productView(p.save(o),true);
    }
    @DeleteMapping("/api/admin/products/{id}") public void del(@PathVariable Long id){ p.findById(id).ifPresent(o->{ o.active=false; p.save(o); }); } }

  @RestController @RequestMapping("/api/account") public static class Account {
    final Users users;
    public Account(Users users){this.users=users;}
    public record ProfileUpdate(String name,String email,String addressName,String addressPhone,String addressHouse,
        String addressArea,String addressLandmark,String addressCity,String addressPincode){}
    @GetMapping public AppUser profile(@AuthenticationPrincipal Long uid){
      return users.findById(uid).orElseThrow(Api::nf);
    }
    @PutMapping @Transactional public AppUser update(@AuthenticationPrincipal Long uid,@RequestBody ProfileUpdate request){
      if(request==null)throw bad("Enter your profile details.");
      AppUser user=users.findById(uid).orElseThrow(Api::nf);
      String name=request.name()==null?"":request.name().trim();
      String email=request.email()==null?"":request.email().trim().toLowerCase(Locale.ROOT);
      String addressName=request.addressName()==null?"":request.addressName().trim();
      String addressPhone=request.addressPhone()==null?"":request.addressPhone().replaceAll("\\D","");
      if(name.length()<2||name.length()>100)throw bad("Name must be between 2 and 100 characters.");
      if(!email.isEmpty()&&(email.length()>255||!email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")))
        throw bad("Enter a valid email address.");
      if(!email.isEmpty()&&users.findByEmailIgnoreCase(email).filter(existing->!existing.id.equals(uid)).isPresent())
        throw new ResponseStatusException(HttpStatus.CONFLICT,"This email address is already registered.");
      String house=trimOrEmpty(request.addressHouse()),area=trimOrEmpty(request.addressArea());
      String landmark=trimOrEmpty(request.addressLandmark()),city=trimOrEmpty(request.addressCity());
      String pincode=trimOrEmpty(request.addressPincode());
      if(house.length()>180||area.length()>180||landmark.length()>180||city.length()>120||pincode.length()>10||addressName.length()>100)
        throw bad("One or more address fields are too long.");
      boolean hasAddress=List.of(house,area,landmark,city,pincode).stream().anyMatch(value->!value.isBlank());
      if(hasAddress&&(house.isBlank()||area.isBlank()||city.isBlank()||!pincode.matches("\\d{6}")||addressName.length()<2||addressPhone.length()!=10))
        throw bad("A saved address needs a recipient name and a separate 10-digit delivery phone number.");
      user.name=name; user.email=email.isEmpty()?null:email;
      user.address=hasAddress?String.join(", ",java.util.stream.Stream.of(house,area,landmark,city,pincode).filter(value->!value.isBlank()).toList()):null;
      user.addressName=hasAddress?addressName:null; user.addressPhone=hasAddress?addressPhone:null;
      user.addressHouse=hasAddress?house:null; user.addressArea=hasAddress?area:null;
      user.addressLandmark=hasAddress&&!landmark.isBlank()?landmark:null; user.addressCity=hasAddress?city:null;
      user.addressPincode=hasAddress?pincode:null;
      return users.save(user);
    }
    static String trimOrEmpty(String value){return value==null?"":value.trim();}
  }

  @RestController public static class Cfg {
    final Settings s; final boolean razorpayConfigured;
    public Cfg(Settings s,@Value("${app.razorpay.key-id:}") String keyId,@Value("${app.razorpay.key-secret:}") String keySecret){
      this.s=s; razorpayConfigured=!keyId.isBlank()&&!keySecret.isBlank();
    }
    @GetMapping("/api/settings/public") public Map<String,String> pub(){ Map<String,String> m=new HashMap<>(); s.findAll().forEach(x->m.put(x.skey,x.svalue)); m.put("razorpay_enabled",String.valueOf(razorpayConfigured)); return m; }
    @PutMapping("/api/admin/settings") public Map<String,String> put(@RequestBody Map<String,String> b){
      if(b==null)throw bad("Provide payment settings.");
      String upi=b.get("upi_id"),payee=b.get("payee_name");
      if(upi!=null&&!upi.isBlank()&&!upi.matches("[A-Za-z0-9._-]{2,100}@[A-Za-z0-9]{2,30}"))throw bad("Enter a valid UPI ID (example: shopname@bank).");
      if(payee!=null&&payee.length()>100)throw bad("Payee name must be 100 characters or fewer.");
      b.forEach((k,v)->{ if(k.matches("upi_id|payee_name|qr_image")&&v!=null){ Setting x=new Setting(); x.skey=k; x.svalue=v.trim(); s.save(x); } }); return pub(); } }

  @RestController public static class StaticDataController {
    final StaticDataConfig config;
    public StaticDataController(StaticDataConfig config){this.config=config;}
    @GetMapping("/api/staticdata") public Map<String,String> publicData(){return config.all();}
    @PutMapping("/api/admin/staticdata") public Map<String,String> update(@RequestBody Map<String,String> changes){
      return config.update(changes);
    }
  }

  @RestController @RequestMapping("/api/orders") public static class Ords {
    final Bookings o; final Products p; final Users u; final Notify n; final OrderImages images; final RepairOrderImages repairImages;
    final StaticDataConfig staticData; final ObjectMapper mapper;
    final String whatsAppCountryCode;
    final String razorpayKeyId,razorpayKeySecret;
    public Ords(Bookings o,Products p,Users u,Notify n,OrderImages images,RepairOrderImages repairImages,StaticDataConfig staticData,ObjectMapper mapper,
        @Value("${app.notifications.whatsapp-country-code:91}") String whatsAppCountryCode,
        @Value("${app.razorpay.key-id:}") String razorpayKeyId,
        @Value("${app.razorpay.key-secret:}") String razorpayKeySecret){
      this.o=o; this.p=p; this.u=u; this.n=n; this.images=images; this.repairImages=repairImages; this.staticData=staticData; this.mapper=mapper;
      this.whatsAppCountryCode=whatsAppCountryCode; this.razorpayKeyId=razorpayKeyId; this.razorpayKeySecret=razorpayKeySecret;
    }
    public record Item(Long productId,String variantId,int qty){}
    public record NewOrder(String type,String service,String description,List<Item> items,String paymentMode,boolean pickup,String address,
      String deliveryName,String deliveryPhone,String footwearType,Integer estimatedQuantity,String showroomLocation){}
    public record PaymentSubmission(String utr){}
    public record QuoteResponse(Boolean accepted){}
    public record Cancellation(String reason){}

@PostMapping(consumes=MediaType.MULTIPART_FORM_DATA_VALUE) @Transactional
    public Booking create(@AuthenticationPrincipal Long uid,@RequestPart("order") NewOrder r,
        @RequestPart(value="images",required=false) List<MultipartFile> uploads){
  if(r==null)throw bad("Provide the order details.");
  if(uploads==null) uploads=List.of();
  int maxImages="REPAIR".equals(r.type())?3:(List.of("CUSTOM","BULK_REPAIR").contains(r.type())?5:0);
  if(!uploads.isEmpty()&&maxImages==0) throw bad("Reference images can only be uploaded for repair, custom, or bulk orders.");
  if(uploads.size()>maxImages) throw bad(maxImages==3?"Upload up to 3 repair images.":"Upload up to 5 reference images.");
      for(MultipartFile image:uploads){
        if(image.isEmpty()||image.getSize()>5L*1024*1024||!validImage(image)) throw bad("Each reference image must be a valid JPG, PNG, or WebP image no larger than 5 MB.");
      }
      AppUser usr=u.findById(uid).orElseThrow(()->bad("Please login again"));
      String type=r.type()==null?"":r.type(); int base=0; String desc;
      String orderAddress="BULK_REPAIR".equals(type)?r.showroomLocation():r.address();
      if(orderAddress==null||orderAddress.trim().length()<5||orderAddress.trim().length()>500)
        throw bad("Enter a valid delivery or showroom address (5–500 characters).");
      if(type.equals("MATERIAL")){
        if(r.items()==null||r.items().isEmpty()) throw bad("Cart is empty");
        StringBuilder sb=new StringBuilder();
        for(Item i:r.items()){
          if(i==null||i.productId()==null||i.qty()<1||i.qty()>1000)throw bad("Choose a valid product and quantity from 1 to 1000.");
          Product pr=p.findById(i.productId()).filter(x->x.active).orElseThrow(()->bad("Product not found"));
          List<Prods.VariantView> choices=readVariants(pr);
          int unitPrice;
          String variantLabel="";
          if(choices.isEmpty()){
            if(i.variantId()!=null&&!i.variantId().isBlank())throw bad("This product does not have selectable variants.");
            if(pr.stock<i.qty())throw bad(pr.name+" is out of stock");
            pr.stock-=i.qty(); unitPrice=pr.price;
          }else{
            if(i.variantId()==null||i.variantId().isBlank())throw bad("Select the product options before adding it to your cart.");
            List<Prods.VariantView> updated=new ArrayList<>(choices.size());
            Prods.VariantView selected=null;
            for(Prods.VariantView choice:choices){
              if(choice.id().equals(i.variantId())){
                if(choice.stock()<i.qty())throw bad(pr.name+" is out of stock for the selected options");
                selected=choice;
                updated.add(new Prods.VariantView(choice.id(),choice.options(),choice.price(),choice.mrp(),choice.stock()-i.qty()));
              }else updated.add(choice);
            }
            if(selected==null)throw bad("The selected product variant is no longer available.");
            try{pr.variantsData=mapper.writeValueAsString(updated);}
            catch(JsonProcessingException ex){throw new IllegalStateException("Could not update variant stock for product "+pr.id,ex);}
            unitPrice=selected.price();
            variantLabel=" ("+String.join(", ",selected.options().entrySet().stream().map(entry->entry.getKey()+": "+entry.getValue()).toList())+")";
          }
          try{base=Math.addExact(base,Math.multiplyExact(unitPrice,i.qty()));}
          catch(ArithmeticException ex){throw bad("Order total is too large.");}
          p.save(pr);
          sb.append(pr.name).append(variantLabel).append(" x").append(i.qty()).append(", ");
        }
        desc=sb.substring(0,sb.length()-2);
      } else if(type.equals("REPAIR")||type.equals("CUSTOM")){
        if(r.service()==null||r.service().isBlank())throw bad("Choose a repair or custom footwear service.");
        if(r.description()!=null&&r.description().length()>700)throw bad("Request details must be 700 characters or fewer.");
        Integer price=SV.get(r.service()); if(price==null) throw bad("Choose a valid repair or custom footwear service."); base=price;
        desc=r.service()+(r.description()==null||r.description().isBlank()?"":" – "+r.description());
      } else if(type.equals("BULK_REPAIR")){
        if(r.footwearType()==null||r.footwearType().isBlank()||r.footwearType().length()>255)
          throw bad("Enter the footwear type (up to 255 characters).");
        if(r.estimatedQuantity()==null||r.estimatedQuantity()<1||r.estimatedQuantity()>100000)
          throw bad("Enter an estimated quantity from 1 to 100000 pairs.");
        if(r.showroomLocation()==null||r.showroomLocation().isBlank()||r.showroomLocation().length()>500)
          throw bad("Enter the showroom location (up to 500 characters).");
        if(r.description()!=null&&r.description().length()>700) throw bad("Repair requirements must be 700 characters or fewer.");
        desc="Bulk showroom repair request. Footwear: "+r.footwearType().trim()+"; estimated quantity: "+r.estimatedQuantity()+" pairs."
          +(r.description()==null||r.description().isBlank()?"":" "+r.description().trim());
      } else throw bad("Invalid order type");
      boolean quoteRequired=List.of("REPAIR","CUSTOM","BULK_REPAIR").contains(type);
      if(!quoteRequired&&!"ONLINE".equals(r.paymentMode())&&!"PAY_ON_DELIVERY".equals(r.paymentMode()))
        throw bad("Choose pay now or pay on delivery");
      Booking x=new Booking(); x.userId=uid; x.userName=usr.name; x.userPhone=usr.phone; x.userEmail=usr.email; x.type=type; x.description=desc;
      x.pickup=r.pickup(); x.address=orderAddress.trim();
      x.deliveryName=quoteRequired?null:cleanOrDefault(r.deliveryName(),usr.name);
      x.deliveryPhone=quoteRequired?null:cleanOrDefault(r.deliveryPhone(),usr.phone);
      if(!quoteRequired&&(x.deliveryName.trim().length()<2||x.deliveryName.length()>100||!x.deliveryPhone.replaceAll("\\D","").matches("\\d{10}")))
        throw bad("Enter a delivery recipient name and a separate 10-digit delivery phone number.");
      x.footwearType="BULK_REPAIR".equals(type)?r.footwearType().trim():null;
      x.estimatedQuantity="BULK_REPAIR".equals(type)?r.estimatedQuantity():null;
      x.total=quoteRequired?0:base+staticData.deliveryCharge(base,r.pickup());
      x.paymentMode=quoteRequired?"QUOTE":r.paymentMode(); x.advance="ONLINE".equals(x.paymentMode)?x.total:0;
      x.paidAmount=0; x.paymentStatus=quoteRequired?"QUOTE_PENDING":("ONLINE".equals(x.paymentMode)?"PENDING":"PAY_ON_DELIVERY");
      if("MATERIAL".equals(type)){
        try{x.itemsData=mapper.writeValueAsString(r.items());}
        catch(JsonProcessingException ex){throw new IllegalStateException("Could not save order item details.",ex);}
      }
      x.status="PLACED"; x.createdAt=LocalDateTime.now();
      o.save(x); x.orderNo="RK-"+(1000+x.id); o.save(x);
      List<OrderNotificationChannels.EmailAttachment> emailAttachments=new ArrayList<>();
      for(MultipartFile upload:uploads){
        try{
          String fileName=Optional.ofNullable(upload.getOriginalFilename()).map(name->name.replaceAll("[^A-Za-z0-9._-]","_")).filter(name->!name.isBlank()).orElse("reference-image");
          String contentType=upload.getContentType();
          byte[] imageData=upload.getBytes();
          if(List.of("REPAIR","BULK_REPAIR").contains(type)){
            RepairOrderImage image=new RepairOrderImage(); image.orderId=x.id;
            image.fileName=fileName; image.contentType=contentType;
            image.imageBase64=Base64.getEncoder().encodeToString(imageData);
            repairImages.save(image);
            emailAttachments.add(new OrderNotificationChannels.EmailAttachment(fileName,contentType,imageData));
          }else{
            OrderImage image=new OrderImage(); image.orderId=x.id;
            image.fileName=fileName; image.contentType=contentType; image.imageData=imageData; images.save(image);
            emailAttachments.add(new OrderNotificationChannels.EmailAttachment(fileName,contentType,imageData));
          }
        }catch(IOException ex){ throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Could not read a reference image."); }
      }
      String whatsAppText=java.net.URLEncoder.encode("Hello "+usr.name+", I reviewed your "+x.orderNo+" request. Let's discuss the quote.",java.nio.charset.StandardCharsets.UTF_8);
      String ownerMessage="New "+type.replace('_',' ')+" booking "+x.orderNo
        +"\nCustomer: "+usr.name+"\nPhone: "+usr.phone+"\nEmail: "+(usr.email==null?"Not provided":usr.email)
        +"\nRequest: "+desc+"\nPickup requested: "+(x.pickup?"Yes":"No")
        +(type.equals("BULK_REPAIR")?"\nShowroom address: "+x.address:"\nDelivery address: "+x.address)
        +(quoteRequired?"":"\nDelivery contact: "+x.deliveryName+" · "+x.deliveryPhone)
        +(type.equals("BULK_REPAIR")?"\nFootwear: "+x.footwearType+"\nEstimated quantity: "+x.estimatedQuantity+" pairs\nShowroom: "+x.address:"")
        +"\n"+(quoteRequired?"Review the request, then send a quote or decline it in the owner dashboard.":"Order total: ₹"+x.total)
        +(uploads.isEmpty()?"":"\nAttached customer photos: "+uploads.size())
        +"\nContact the customer on WhatsApp: https://wa.me/91"+usr.phone+"?text="+whatsAppText;
      if(!emailAttachments.isEmpty()) n.admin(ownerMessage,x.orderNo,emailAttachments);
      else n.admin(ownerMessage,x.orderNo);
      n.user(uid,quoteRequired?"🎉 Order received! Your "+type.toLowerCase().replace('_',' ')+" request "+x.orderNo+" is with our team. We’ll review the details and send you a quote."
        :"🎉 Order received! Thank you for choosing Raj Kumar Shoe Repairing. Order "+x.orderNo+" is confirmed as received. Total: ₹"+x.total+("ONLINE".equals(x.paymentMode)?" · Pay securely via Razorpay.":" · Payment is due on delivery.")+"\nDelivery address: "+x.address,x.orderNo);
      return x; }

    List<Prods.VariantView> readVariants(Product product){
      if(product.variantsData==null||product.variantsData.isBlank())return List.of();
      try{return mapper.readValue(product.variantsData,new TypeReference<List<Prods.VariantView>>(){});}
      catch(JsonProcessingException ex){throw new IllegalStateException("Stored product variants are invalid for product "+product.id,ex);}
    }
    static String cleanOrDefault(String value,String fallback){return value==null||value.isBlank()?fallback:value.trim();}

    public record RazorpayVerification(String razorpayOrderId,String razorpayPaymentId,String razorpaySignature){}
    @PostMapping("/{id}/razorpay-order") @Transactional
    public Map<String,Object> createRazorpayOrder(@AuthenticationPrincipal Long uid,@PathVariable Long id){
      Booking order=o.findById(id).filter(item->item.userId.equals(uid)).orElseThrow(Api::nf);
      requireRazorpayConfigured();
      ensurePendingOnlineOrder(order);
      if(order.razorpayOrderId==null){
        try{
          Map<String,Object> payload=Map.of("amount",Math.multiplyExact((long)order.total,100L),"currency","INR",
            "receipt",order.orderNo,"notes",Map.of("app_order_id",order.id.toString()));
          JsonNode response=razorpayRequest("orders","POST",payload);
          String gatewayId=response.path("id").asText("");
          if(gatewayId.isBlank())throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Razorpay did not return a payment order.");
          order.razorpayOrderId=gatewayId;
          o.save(order);
        }catch(ArithmeticException ex){throw bad("Order total is too large for online payment.");}
      }
      return Map.of("keyId",razorpayKeyId,"razorpayOrderId",order.razorpayOrderId,
        "amount",Math.multiplyExact((long)order.total,100L),"currency","INR",
        "expiresAt",order.createdAt.plusMinutes(10).toString(),"orderNo",order.orderNo,
        "customerName",order.deliveryName==null?order.userName:order.deliveryName,
        "customerPhone",order.deliveryPhone==null?order.userPhone:order.deliveryPhone);
    }

    @PostMapping("/{id}/razorpay-verify") @Transactional
    public Booking verifyRazorpayPayment(@AuthenticationPrincipal Long uid,@PathVariable Long id,
        @RequestBody RazorpayVerification payment){
      Booking order=o.findById(id).filter(item->item.userId.equals(uid)).orElseThrow(Api::nf);
      requireRazorpayConfigured();
      if(payment==null||!Objects.equals(order.razorpayOrderId,payment.razorpayOrderId())
          ||payment.razorpayPaymentId()==null||payment.razorpaySignature()==null)
        throw bad("Payment confirmation does not match this order.");
      if("PAID".equals(order.paymentStatus)&&Objects.equals(order.razorpayPaymentId,payment.razorpayPaymentId()))return order;
      if(!MessageDigest.isEqual(razorpaySignature(payment.razorpayOrderId(),payment.razorpayPaymentId())
          .getBytes(java.nio.charset.StandardCharsets.US_ASCII),
          payment.razorpaySignature().getBytes(java.nio.charset.StandardCharsets.US_ASCII)))
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Razorpay payment signature is invalid.");
      JsonNode gatewayPayment=razorpayRequest("payments/"+payment.razorpayPaymentId(),"GET",null);
      if(!Objects.equals(order.razorpayOrderId,gatewayPayment.path("order_id").asText())
          ||gatewayPayment.path("amount").asLong(-1)!=Math.multiplyExact((long)order.total,100L)
          ||!"INR".equals(gatewayPayment.path("currency").asText()))
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Razorpay payment amount or order does not match.");
      String status=gatewayPayment.path("status").asText();
      boolean timely="PENDING".equals(order.paymentStatus)&&"PLACED".equals(order.status)
        &&order.createdAt!=null&&order.createdAt.plusMinutes(10).isAfter(LocalDateTime.now());
      if(!timely){
        if("captured".equals(status)){
          JsonNode refund=razorpayRequest("payments/"+payment.razorpayPaymentId()+"/refund","POST",
            Map.of("amount",Math.multiplyExact((long)order.total,100L),"notes",Map.of("reason","Checkout expired", "app_order_id",order.id.toString())));
          boolean reserved="PENDING".equals(order.paymentStatus)&&"PLACED".equals(order.status);
          if(reserved)releaseReservedStock(order);
          order.razorpayPaymentId=payment.razorpayPaymentId();
          order.paidAmount=order.total; order.paymentStatus="REFUND_PENDING"; order.status="CANCELLED";
          o.save(order);
          n.user(uid,"Your payment for "+order.orderNo+" arrived after checkout expired. A refund ("+refund.path("id").asText("reference pending")+") has been initiated. Contact the shop if you need help.",order.orderNo);
          return order;
        }
        throw new ResponseStatusException(HttpStatus.CONFLICT,"This payment session expired. Start a new order; any captured amount will be automatically refunded.");
      }
      if("authorized".equals(status)){
        gatewayPayment=razorpayRequest("payments/"+payment.razorpayPaymentId()+"/capture","POST",
          Map.of("amount",Math.multiplyExact((long)order.total,100L),"currency","INR"));
        status=gatewayPayment.path("status").asText();
      }
      if(!"captured".equals(status))throw new ResponseStatusException(HttpStatus.CONFLICT,"Payment was not captured. Please try again or choose pay on delivery.");
      order.razorpayPaymentId=payment.razorpayPaymentId();
      order.paidAmount=order.total; order.paymentStatus="PAID"; order.status="CONFIRMED";
      Booking saved=o.save(order);
      n.user(uid,"✅ Payment of ₹"+order.total+" received securely for "+order.orderNo+". Your order is confirmed.",order.orderNo);
      n.admin("💰 Razorpay payment of ₹"+order.total+" captured for "+order.orderNo+".",order.orderNo);
      return saved;
    }

    @PostMapping("/{id}/payment-failed") @Transactional
    public Booking failRazorpayPayment(@AuthenticationPrincipal Long uid,@PathVariable Long id){
      Booking order=o.findById(id).filter(item->item.userId.equals(uid)).orElseThrow(Api::nf);
      if(!"ONLINE".equals(order.paymentMode)||!"PENDING".equals(order.paymentStatus)||!"PLACED".equals(order.status))
        throw bad("This payment is no longer pending.");
      expireOnlineOrder(order,"Payment was not completed. No payment was confirmed. Contact the shop if your bank shows a debit.");
      return order;
    }

    @Scheduled(fixedDelay=60000)
    @Transactional
    public void expirePendingPayments(){
      LocalDateTime deadline=LocalDateTime.now().minusMinutes(10);
      for(Booking order:o.findByPaymentModeAndPaymentStatusAndStatus("ONLINE","PENDING","PLACED")){
        if(order.createdAt!=null&&order.createdAt.isBefore(deadline))
          expireOnlineOrder(order,"Your payment session expired after 10 minutes. No payment was confirmed. Contact the shop if your bank shows a debit.");
      }
    }

    void expireOnlineOrder(Booking order,String message){
      releaseReservedStock(order);
      order.status="CANCELLED"; order.paymentStatus="DECLINED"; order.adminNote="Razorpay checkout expired or failed.";
      o.save(order);
      n.user(order.userId,message+" Order "+order.orderNo+".",order.orderNo);
      n.admin("Razorpay payment session expired for "+order.orderNo+".",order.orderNo);
    }

    void releaseReservedStock(Booking order){
      if(!"MATERIAL".equals(order.type)||order.itemsData==null||order.itemsData.isBlank())return;
      List<Item> items;
      try{items=mapper.readValue(order.itemsData,new TypeReference<List<Item>>(){});}
      catch(JsonProcessingException ex){throw new IllegalStateException("Could not restore reserved inventory for order "+order.orderNo,ex);}
      for(Item item:items){
        Product product=p.findById(item.productId()).orElse(null);
        if(product==null)continue;
        List<Prods.VariantView> choices=readVariants(product);
        if(choices.isEmpty()){
          product.stock=Math.addExact(product.stock,item.qty());
        }else{
          List<Prods.VariantView> updated=new ArrayList<>(choices.size());
          for(Prods.VariantView choice:choices){
            if(choice.id().equals(item.variantId()))
              updated.add(new Prods.VariantView(choice.id(),choice.options(),choice.price(),choice.mrp(),Math.addExact(choice.stock(),item.qty())));
            else updated.add(choice);
          }
          try{product.variantsData=mapper.writeValueAsString(updated);}
          catch(JsonProcessingException ex){throw new IllegalStateException("Could not restore variant inventory for product "+product.id,ex);}
        }
        p.save(product);
      }
      order.itemsData=null;
    }

    void ensurePendingOnlineOrder(Booking order){
      if(!"ONLINE".equals(order.paymentMode)||!"PENDING".equals(order.paymentStatus)||!"PLACED".equals(order.status))
        throw bad("This order is no longer eligible for online payment.");
      if(order.createdAt==null||!order.createdAt.plusMinutes(10).isAfter(LocalDateTime.now()))
        throw new ResponseStatusException(HttpStatus.GONE,"Payment session expired. Please place the order again.");
    }

    void requireRazorpayConfigured(){
      if(razorpayKeyId.isBlank()||razorpayKeySecret.isBlank())
        throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"Online payments are not configured. Choose pay on delivery or contact the shop.");
    }

    String razorpaySignature(String orderId,String paymentId){
      try{
        javax.crypto.Mac mac=javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(razorpayKeySecret.getBytes(java.nio.charset.StandardCharsets.UTF_8),"HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal((orderId+"|"+paymentId).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
      }catch(java.security.GeneralSecurityException ex){throw new IllegalStateException("HMAC-SHA256 is unavailable.",ex);}
    }

    JsonNode razorpayRequest(String path,String method,Map<String,Object> payload){
      try{
        String credentials=Base64.getEncoder().encodeToString((razorpayKeyId+":"+razorpayKeySecret).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        java.net.http.HttpRequest.Builder builder=java.net.http.HttpRequest.newBuilder()
          .uri(java.net.URI.create("https://api.razorpay.com/v1/"+path))
          .timeout(java.time.Duration.ofSeconds(15))
          .header("Authorization","Basic "+credentials)
          .header("Content-Type","application/json");
        if("GET".equals(method))builder.GET();
        else builder.method(method,java.net.http.HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload)));
        java.net.http.HttpResponse<String> response=java.net.http.HttpClient.newHttpClient().send(builder.build(),
          java.net.http.HttpResponse.BodyHandlers.ofString());
        JsonNode result=mapper.readTree(response.body());
        if(response.statusCode()<200||response.statusCode()>=300)
          throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Razorpay could not complete the payment request. Please retry or choose pay on delivery.");
        return result;
      }catch(ResponseStatusException ex){throw ex;}
      catch(InterruptedException ex){
        Thread.currentThread().interrupt();
        throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Razorpay payment request was interrupted. Please retry.",ex);
      }catch(IOException ex){
        throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Razorpay could not be reached. Please retry or choose pay on delivery.",ex);
      }
    }

    @PostMapping("/{id}/payment") @Transactional public Booking pay(@AuthenticationPrincipal Long uid,@PathVariable Long id,@RequestBody PaymentSubmission payment){
      Booking x=o.findById(id).filter(y->y.userId.equals(uid)).orElseThrow(Api::nf);
      if(payment==null)throw bad("Enter the UPI transaction reference.");
      if(!"ONLINE".equals(x.paymentMode)) throw bad("This order is set to pay on delivery.");
      if(!"PENDING".equals(x.paymentStatus)) throw bad("Payment has already been submitted.");
      if(payment.utr()==null||!payment.utr().matches("[A-Za-z0-9]{8,22}")) throw bad("Enter the 8–22 character UPI reference number (UTR) from Google Pay.");
      x.utr=payment.utr(); x.paymentStatus="AWAITING_VERIFICATION"; o.save(x);
      n.admin("💰 Google Pay/UPI payment of ₹"+x.total+" submitted for "+x.orderNo+" (UTR "+x.utr+"). Verify the payment in your bank/UPI app before approving.",x.orderNo);
      n.user(uid,"Your Google Pay/UPI payment for "+x.orderNo+" was submitted. The owner will verify the UTR before confirming.",x.orderNo);
      return x; }

    @PostMapping("/{id}/quote-response") @Transactional public Booking quoteResponse(
        @AuthenticationPrincipal Long uid,@PathVariable Long id,@RequestBody QuoteResponse response){
      Booking x=o.findById(id).filter(order->order.userId.equals(uid)).orElseThrow(Api::nf);
      if(response==null||response.accepted()==null)throw bad("Choose whether to accept or decline the quote.");
      if(!"AWAITING_CUSTOMER_ACCEPTANCE".equals(x.paymentStatus)||!"QUOTE".equals(x.paymentMode))
        throw bad("There is no owner quote awaiting your response.");
      if(response.accepted()){
        x.status="CONFIRMED"; x.paymentMode="PAY_ON_DELIVERY"; x.paymentStatus="PAY_ON_DELIVERY";
        n.user(uid,"You accepted the ₹"+x.total+" quote for "+x.orderNo+". The amount is due on delivery.",x.orderNo);
        n.admin("✅ Customer "+x.userName+" accepted the ₹"+x.total+" quote for "+x.orderNo+".",x.orderNo);
      }else{
        x.status="DECLINED"; x.paymentStatus="NONE";
        n.user(uid,"You declined the owner’s quote for "+x.orderNo+".",x.orderNo);
        n.admin("Customer "+x.userName+" declined the quote for "+x.orderNo+".",x.orderNo);
      }
      return o.save(x);
    }

    @PostMapping("/{id}/cancel") @Transactional public Booking cancel(
        @AuthenticationPrincipal Long uid,@PathVariable Long id,@RequestBody(required=false) Cancellation request){
      Booking order=o.findById(id).filter(item->item.userId.equals(uid)).orElseThrow(Api::nf);
      if(!Set.of("PLACED","CONFIRMED").contains(order.status))
        throw bad("This order can no longer be cancelled. Contact the shop for assistance.");
      String reason=request==null||request.reason()==null?"":request.reason().trim();
      if(reason.length()>300)throw bad("Cancellation reason must be 300 characters or fewer.");
      order.status="CANCELLED";
      boolean refundRequired=order.paidAmount>0||"AWAITING_VERIFICATION".equals(order.paymentStatus);
      releaseReservedStock(order);
      order.paymentStatus=refundRequired?"REFUND_PENDING":"NONE";
      order.adminNote=reason.isBlank()?"Cancelled by customer":reason;
      o.save(order);
      String customerMessage=String.format(NotificationMessages.CUSTOMER_CANCELLED_ORDER,order.orderNo,
        refundRequired?"Any payment received is being reviewed for refund.":"No payment was collected.");
      n.user(uid,customerMessage,order.orderNo);
      n.admin(Api.cancellationAdminMessage(order,reason,"Customer requested cancellation.",whatsAppCountryCode),order.orderNo);
      return order;
    }

    @RestController @RequestMapping("/api/admin/orders") public static class ImagesController {
      final OrderImages images; final RepairOrderImages repairImages; final Bookings orders;
      public ImagesController(OrderImages images,RepairOrderImages repairImages,Bookings orders){
        this.images=images; this.repairImages=repairImages; this.orders=orders;
      }
      public record ImageView(Long id,String fileName,String contentType,String data){}
      @GetMapping("/{orderId}/images") public List<ImageView> list(@PathVariable Long orderId){
        if(!orders.existsById(orderId)) throw Api.nf();
        List<ImageView> result=new ArrayList<>();
        images.findByOrderIdOrderByIdAsc(orderId).forEach(x->result.add(new ImageView(
          x.id,x.fileName,x.contentType,"data:"+x.contentType+";base64,"+Base64.getEncoder().encodeToString(x.imageData))));
        repairImages.findByOrderIdOrderByIdAsc(orderId).forEach(x->result.add(new ImageView(
          x.id,x.fileName,x.contentType,"data:"+x.contentType+";base64,"+x.imageBase64)));
        return result;
      }
    }
    @GetMapping public List<Booking> mine(@AuthenticationPrincipal Long uid){ return o.findByUserIdOrderByIdDesc(uid); }

  }
  @RestController @RequestMapping("/api/notifications") public static class Nots {
    final Notes notes; public Nots(Notes n){ notes=n; }
    @GetMapping public List<Notification> list(@AuthenticationPrincipal Long uid,Authentication a){
      return (isAdmin(a)?notes.findByForAdminTrueOrderByIdDesc():notes.findByUserIdOrderByIdDesc(uid)).stream().limit(50).toList(); }
    @PostMapping("/read") public void read(@AuthenticationPrincipal Long uid,Authentication a){ List<Notification> l=list(uid,a); l.forEach(x->x.seen=true); notes.saveAll(l); }
    @DeleteMapping @Transactional public void clear(@AuthenticationPrincipal Long uid,Authentication a){
      if(isAdmin(a)) notes.deleteByForAdminTrue();
      else notes.deleteByUserId(uid);
    }
  }

  @RestController public static class CustomerFeedbackApi {
    final Feedback feedback; final Bookings bookings;
    public CustomerFeedbackApi(Feedback feedback,Bookings bookings){this.feedback=feedback;this.bookings=bookings;}

    public record Submission(Integer rating,String review){}
    public record FeedbackStatus(Long orderId,String orderNo,String orderStatus,boolean submitted){}
    public record FeedbackView(Long id,Long orderId,String orderNo,String customerName,int rating,String review,LocalDateTime createdAt){}

    @GetMapping("/api/feedback/status/{orderId}")
    public FeedbackStatus status(@AuthenticationPrincipal Long uid,@PathVariable Long orderId,Authentication authentication){
      requireCustomer(authentication);
      Booking order=bookings.findById(orderId).filter(item->item.userId.equals(uid)).orElseThrow(Api::nf);
      return new FeedbackStatus(order.id,order.orderNo,order.status,feedback.existsByOrderId(order.id));
    }

    @PostMapping("/api/feedback/{orderId}") @Transactional
    public Map<String,String> submitForOrder(@AuthenticationPrincipal Long uid,@PathVariable Long orderId,
        @RequestBody Submission request,Authentication authentication){
      requireCustomer(authentication);
      if(request==null||request.rating()==null||request.rating()<1||request.rating()>5)
        throw bad("Choose a star rating from 1 to 5.");
      if(request.review()==null||request.review().trim().length()<5||request.review().trim().length()>1000)
        throw bad("Feedback must be between 5 and 1000 characters.");
      Booking order=bookings.findById(orderId).filter(item->item.userId.equals(uid)).orElseThrow(Api::nf);
      if(!"DELIVERED".equals(order.status))throw bad("Feedback is available after your order has been delivered.");
      if(feedback.existsByOrderId(order.id))throw bad("Feedback has already been submitted for this order.");
      CustomerFeedback entry=new CustomerFeedback(); entry.orderId=order.id; entry.userId=uid;
      entry.orderNo=order.orderNo; entry.customerName=order.userName; entry.rating=request.rating();
      entry.review=request.review().trim(); entry.createdAt=LocalDateTime.now(); feedback.save(entry);
      return Map.of("message","Thank you! Your feedback has been submitted.");
    }

    @GetMapping("/api/admin/feedback")
    public List<FeedbackView> adminList(Authentication authentication){
      if(!isAdmin(authentication))throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Admin access required.");
      return feedback.findAllByOrderByCreatedAtDesc().stream().map(item->new FeedbackView(
        item.id,item.orderId,item.orderNo,item.customerName,item.rating,item.review,item.createdAt)).toList();
    }

    private static void requireCustomer(Authentication authentication){
      if(authentication==null||!authentication.isAuthenticated()||isAdmin(authentication))
        throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Customer sign-in is required.");
    }
  }

  @RestController @RequestMapping("/api/admin/orders") public static class AdminOrds {
    final Bookings o; final Users users; final Notify n; final com.rajkumar.shoe.config.AppServiceContext appServiceContext;
    final String whatsAppCountryCode; final Ords orderService;
    public AdminOrds(Bookings o,Users users,Notify n, com.rajkumar.shoe.config.AppServiceContext appServiceContext,Ords orderService,
        @Value("${app.notifications.whatsapp-country-code:91}") String whatsAppCountryCode){
      this.o=o; this.users=users; this.n=n; this.appServiceContext=appServiceContext; this.whatsAppCountryCode=whatsAppCountryCode; this.orderService=orderService;
    }
    public record Dec(boolean approve,String note){}
    public record St(String status){}
    public record Quote(int amount,String note){}
    Booking get(Long id){ return o.findById(id).orElseThrow(Api::nf); }
    @GetMapping public List<Booking> all(){ return o.findAllByOrderByIdDesc(); }

    @PostMapping("/{id}/quote") public Booking quote(@PathVariable Long id,@RequestBody Quote quote){
      Booking x=get(id);
      if(quote==null)throw bad("Enter the quote amount.");
      if(!List.of("REPAIR","CUSTOM","BULK_REPAIR").contains(x.type)||!"QUOTE".equals(x.paymentMode)
          ||!"QUOTE_PENDING".equals(x.paymentStatus)||!"PLACED".equals(x.status))
        throw bad("This order is not waiting for an owner quote.");
      if(quote.amount()<1||quote.amount()>10000000) throw bad("Quote amount must be between ₹1 and ₹10,000,000.");
      if(quote.note()!=null&&quote.note().length()>300) throw bad("Quote note must be 300 characters or fewer.");
      x.total=quote.amount(); x.paymentStatus="AWAITING_CUSTOMER_ACCEPTANCE"; x.adminNote=quote.note();
      o.save(x);
      String details=quote.note()==null||quote.note().isBlank()?"":" "+quote.note().trim();
      n.quoteCustomer(x.userId,"Raj Kumar Shoe Repairing has quoted ₹"+x.total+" for order "+x.orderNo+". Please review and accept or decline in My orders."+details,x.orderNo);
      return x;
    }

    @PostMapping("/{id}/decision") public Booking decide(@PathVariable Long id,@RequestBody Dec d){
      if(d==null)throw bad("Choose whether to approve or decline this order.");
      if(d.note()!=null&&d.note().length()>300)throw bad("Decline note must be 300 characters or fewer.");
      Booking x=get(id); if(!"PLACED".equals(x.status)) throw bad("Already decided");
      if(d.approve()&&"QUOTE_PENDING".equals(x.paymentStatus)) throw bad("Send a price quote first.");
      if(d.approve()&&"AWAITING_CUSTOMER_ACCEPTANCE".equals(x.paymentStatus)) throw bad("Wait for the customer to respond to the quote.");
      String note=d.note()==null||d.note().isBlank()?"":" Note: "+d.note(); x.adminNote=d.note();
      if(d.approve()){ if("ONLINE".equals(x.paymentMode)&&!"AWAITING_VERIFICATION".equals(x.paymentStatus)) throw bad("Verify the submitted Google Pay/UPI payment before approving this order."); x.status="CONFIRMED"; if("ONLINE".equals(x.paymentMode)){ x.paymentStatus="PAID"; x.paidAmount=x.total; } else x.paymentStatus="PAY_ON_DELIVERY";
        n.user(x.userId,"✅ Your order has been reviewed and approved! Order "+x.orderNo+" is now confirmed."+("PAY_ON_DELIVERY".equals(x.paymentStatus)?" Total ₹"+x.total+" is payable on delivery.":" Payment received and verified."),x.orderNo);
      } else { x.status="DECLINED";
        orderService.releaseReservedStock(x);
        boolean refundRequired=x.paidAmount>0||"AWAITING_VERIFICATION".equals(x.paymentStatus);
        if(refundRequired){ x.paymentStatus="REFUND_PENDING"; n.user(x.userId,String.format(NotificationMessages.OWNER_CANCELLED_ORDER,x.orderNo,"Any payment received is being reviewed for refund."+note),x.orderNo); }
        else { x.paymentStatus="NONE"; n.user(x.userId,String.format(NotificationMessages.OWNER_CANCELLED_ORDER,x.orderNo,note),x.orderNo); }
        n.admin(Api.cancellationAdminMessage(x,d.note(),"Owner cancelled this order.",whatsAppCountryCode),x.orderNo); }
      return o.save(x); }

    @PostMapping("/{id}/cancel") @Transactional public Booking cancel(@PathVariable Long id,@RequestBody(required=false) Ords.Cancellation request){
      Booking order=get(id);
      if(Set.of("DELIVERED","DECLINED","CANCELLED").contains(order.status))
        throw bad("This order is already complete or cancelled.");
      String reason=request==null||request.reason()==null?"":request.reason().trim();
      if(reason.length()>300)throw bad("Cancellation reason must be 300 characters or fewer.");
      order.status="CANCELLED";
      boolean refundRequired=order.paidAmount>0||"AWAITING_VERIFICATION".equals(order.paymentStatus);
      orderService.releaseReservedStock(order);
      order.paymentStatus=refundRequired?"REFUND_PENDING":"NONE";
      order.adminNote=reason.isBlank()?"Cancelled by the shop":reason;
      o.save(order);
      n.user(order.userId,String.format(NotificationMessages.OWNER_CANCELLED_ORDER,order.orderNo,
        refundRequired?"Any payment received is being reviewed for refund.":"No payment was collected."+(reason.isBlank()?"":" "+reason)),order.orderNo);
      n.admin(Api.cancellationAdminMessage(order,reason,"Owner cancelled this order.",whatsAppCountryCode),order.orderNo);
      return order;
    }

    @PostMapping("/{id}/refunded") public Booking refunded(@PathVariable Long id){
      Booking x=get(id); if(!"REFUND_PENDING".equals(x.paymentStatus)) throw bad("No refund pending");
      x.paymentStatus="REFUNDED"; n.user(x.userId,"💸 Refund of ₹"+x.paidAmount+" for "+x.orderNo+" has been sent.",x.orderNo); return o.save(x); }

    @PostMapping("/{id}/status") public Booking status(@PathVariable Long id,@RequestBody St s){
      if(s==null||s.status()==null||s.status().isBlank())throw bad("Choose the new order status.");
      Booking x=get(id); if(x.status.equals("PLACED")||x.status.equals("DECLINED")) throw bad("Approve the order first");
      if(!List.of("IN_PROGRESS","READY","OUT_FOR_DELIVERY","DELIVERED").contains(s.status())) throw bad("Invalid status");
      x.status=s.status(); if(s.status().equals("DELIVERED")){ x.paymentStatus="PAID"; x.paidAmount=x.total; }
      String message=s.status().equals("DELIVERED")
        ?appServiceContext.buildOrderDeliveredMessage(x.orderNo)
        :appServiceContext.buildOrderStatusMessage(x.orderNo, s.status());
      if(s.status().equals("DELIVERED"))n.delivered(x.userId,message,x.orderNo,x.id);
      else n.user(x.userId,message,x.orderNo);
      return o.save(x); } }

  @Component public static class Seed implements CommandLineRunner {
    final Users users; final Settings s; final PasswordEncoder enc; final String phone,pass;
    public Seed(Users u,Settings s,PasswordEncoder e,@Value("${app.admin-phone}") String ph,@Value("${app.admin-password}") String pw){ users=u; this.s=s; enc=e; phone=ph; pass=pw; }
    @Override public void run(String... a){
      if(users.findByPhone(phone).isEmpty()){
        AppUser u=users.findByPhone("9999999999").filter(x->"ADMIN".equals(x.role)).orElseGet(()->{
          AppUser owner=new AppUser(); owner.name="Owner"; owner.passwordHash=enc.encode(pass); owner.role="ADMIN"; return owner;
        });
        u.phone=phone; users.save(u);
      }
      Map<String,String> d=Map.of("upi_id","yourname@upi","payee_name","Raj Kumar Shoe Repairing","qr_image","");
      d.forEach((k,v)->{ if(!s.existsById(k)){ Setting x=new Setting(); x.skey=k; x.svalue=v; s.save(x); } }); } }
}
