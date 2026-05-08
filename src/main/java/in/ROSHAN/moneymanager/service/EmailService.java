package in.ROSHAN.moneymanager.service;

import org.springframework.stereotype.Service;

/**
 * EmailService stubbed out. Email sending has been removed from the project.
 * Methods are no-ops so existing controllers can remain functional without SMTP.
 */
@Service
public class EmailService {

    public void sendEmail(String to, String subject, String body) {
        // Email sending disabled.
    }

    public void sendEmailWithAttachment(String to, String subject, String body, byte[] attachment, String filename) {
        // Email sending disabled.
    }
}
