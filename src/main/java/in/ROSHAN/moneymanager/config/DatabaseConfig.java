package in.ROSHAN.moneymanager.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("prod")
public class DatabaseConfig {
    
    // This configuration will only be active in production
    // If database connection fails, the application will still start
    // but database-dependent features won't work
}
