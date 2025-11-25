package in.ROSHAN.moneymanager.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.Map;

@RestController
public class TestController {

    @GetMapping("/")
    public Map<String, Object> root() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "SUCCESS");
        response.put("message", "Money Manager Backend is running!");
        response.put("version", "1.0.0");
        response.put("timestamp", System.currentTimeMillis());
        return response;
    }

    @GetMapping("/test")
    public Map<String, Object> test() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "OK");
        response.put("message", "Test endpoint working");
        response.put("timestamp", System.currentTimeMillis());
        return response;
    }
}
