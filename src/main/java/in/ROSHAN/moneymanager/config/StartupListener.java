package in.ROSHAN.moneymanager.config;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class StartupListener {

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        System.out.println("==========================================");
        System.out.println("Money Manager Backend Started Successfully!");
        System.out.println("Application is ready to accept requests");
        System.out.println("==========================================");
    }
}
