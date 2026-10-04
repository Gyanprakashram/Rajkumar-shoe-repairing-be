package com.rajkumar.shoe.config;

import com.rajkumar.shoe.Api;
import com.rajkumar.shoe.Models.StaticData;
import com.rajkumar.shoe.Models.StaticDataEntry;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Service
public class StaticDataConfig {
  private static final Pattern KEY_PATTERN=Pattern.compile("(shop|delivery|rate-limit|service)\\.[a-z0-9._-]{1,80}");
  private final StaticData repository;
  private final Map<String,String> values=new ConcurrentHashMap<>();

  public StaticDataConfig(StaticData repository){
    this.repository=repository;
    Map<String,String> defaults=Map.of(
      "shop.name","Raj Kumar Shoe Repairing",
      "shop.address","Bistupur, Jamshedpur, Jharkhand",
      "shop.established_year","1984",
      "shop.phone","9263627052",
      "shop.hours","Mon-Sun 10am-8pm",
      "delivery.free_threshold","500",
      "delivery.fee","50",
      "rate-limit.api-per-minute","120",
      "rate-limit.auth-per-minute","10",
      "rate-limit.order-per-minute","10");
    defaults.forEach((key,value)->{
      StaticDataEntry entry=repository.findById(key).orElseGet(()->{
        StaticDataEntry initial=new StaticDataEntry(); initial.key=key; initial.value=value;
        return repository.save(initial);
      });
      values.put(key,entry.value);
    });
    repository.findAll().forEach(entry->values.put(entry.key,entry.value));
  }

  public Map<String,String> all(){ return Map.copyOf(values); }

  public int rateLimit(String key,int fallback){
    try{
      int configured=Integer.parseInt(values.getOrDefault(key,String.valueOf(fallback)));
      return Math.max(1,Math.min(configured,5000));
    }catch(NumberFormatException ex){ throw new IllegalStateException("Invalid rate-limit configuration for "+key,ex); }
  }

  public int deliveryCharge(int base,boolean pickup){
    try{
      int threshold=Integer.parseInt(values.getOrDefault("delivery.free_threshold","500"));
      int fee=Integer.parseInt(values.getOrDefault("delivery.fee","50"));
      if(threshold<0||fee<0)throw new IllegalStateException("Delivery configuration cannot be negative.");
      return pickup&&base<threshold?fee:0;
    }catch(NumberFormatException ex){throw new IllegalStateException("Delivery settings must be whole numbers.",ex);}
  }

  @Transactional
  public Map<String,String> update(Map<String,String> changes){
    if(changes==null)throw new IllegalArgumentException("Provide one or more configuration values.");
    changes.forEach((key,value)->{
      if(key==null||!KEY_PATTERN.matcher(key).matches())
        throw new IllegalArgumentException("Static-data keys must use shop.*, delivery.*, rate-limit.*, or service.*.");
      if(value==null||value.trim().isEmpty()||value.length()>1000)
        throw new IllegalArgumentException("Static-data values must not be empty or exceed 1000 characters.");
      validateRateLimit(key,value);
    });
    changes.forEach((key,value)->{
      StaticDataEntry entry=repository.findById(key).orElseGet(StaticDataEntry::new);
      entry.key=key; entry.value=value.trim();
      repository.save(entry);
    });
    Runnable refresh=()->changes.forEach((key,value)->values.put(key,value.trim()));
    if(TransactionSynchronizationManager.isSynchronizationActive()){
      TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
        @Override public void afterCommit(){refresh.run();}
      });
    }else refresh.run();
    Map<String,String> response=new java.util.HashMap<>(values);
    changes.forEach((key,value)->response.put(key,value.trim()));
    return Map.copyOf(response);
  }

  private static void validateRateLimit(String key,String value){
    if(key.equals("delivery.free_threshold")||key.equals("delivery.fee")){
      validateNonnegativeInteger(key,value);
      return;
    }
    if(!key.startsWith("rate-limit."))return;
    final int limit;
    try{limit=Integer.parseInt(value);}
    catch(NumberFormatException ex){throw new IllegalArgumentException("Rate limits must be whole numbers.");}
    int maximum=key.endsWith("api-per-minute")?5000:key.endsWith("auth-per-minute")?60:500;
    if(limit<1||limit>maximum)throw new IllegalArgumentException("Rate-limit values must be between 1 and "+maximum+".");
  }

  private static void validateNonnegativeInteger(String key,String value){
    try{
      int amount=Integer.parseInt(value);
      if(amount<0||amount>1_000_000)throw new IllegalArgumentException(key+" must be between 0 and 1000000.");
    }catch(NumberFormatException ex){throw new IllegalArgumentException(key+" must be a whole number.");}
  }
}
