package in.roshan.moneymanager.service;

import in.roshan.moneymanager.repository.ProfileRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationService {

    private final ProfileRepository profileRepository;
    private final ExpenseService expenseService;

    @Scheduled(cron = "0 0 22 * * *", zone = "IST")
    public void sendDailyIncomeExpenseReminder() {
        log.info("Email service removed - Daily reminder job disabled");
    }

    @Scheduled(cron = "0 0 23 * * *", zone = "IST")
    public void sendDailyExpenseSummary() {
        log.info("Email service removed - Daily expense summary job disabled");
    }
}
