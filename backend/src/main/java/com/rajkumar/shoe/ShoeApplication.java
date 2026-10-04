package com.rajkumar.shoe;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import java.util.concurrent.Executor;
import java.lang.reflect.Method;
@SpringBootApplication
@EnableJpaRepositories(considerNestedRepositories = true)
@EnableAsync
public class ShoeApplication {
  private static final Logger log=LoggerFactory.getLogger(ShoeApplication.class);
  public static void main(String[] a){ SpringApplication.run(ShoeApplication.class,a); }

  @Bean("notificationExecutor")
  Executor notificationExecutor(){
    ThreadPoolTaskExecutor executor=new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(2);
    executor.setMaxPoolSize(4);
    executor.setQueueCapacity(200);
    executor.setThreadNamePrefix("order-notification-");
    executor.setTaskDecorator(task->{
      var context=MDC.getCopyOfContextMap();
      return ()->{
        if(context==null)MDC.clear();else MDC.setContextMap(context);
        try{task.run();}finally{MDC.clear();}
      };
    });
    executor.initialize();
    return executor;
  }

  @Bean AsyncUncaughtExceptionHandler asyncUncaughtExceptionHandler(){
    return (Throwable error,Method method,Object...params)->{
      log.error("async_method_failed method={} exception={}",method.toGenericString(),TraceLogSupport.safeException(error));
      TraceLogSupport.logStack(log,"async_method_failure_stack",error);
    };
  }
}
