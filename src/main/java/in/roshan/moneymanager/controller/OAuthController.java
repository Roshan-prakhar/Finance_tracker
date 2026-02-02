package in.roshan.moneymanager.controller;

import in.roshan.moneymanager.entity.ProfileEntity;
import in.roshan.moneymanager.service.ProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final ProfileService profileService;

    @Value("${money.manager.frontend.url}")
    private String frontendUrl;

    @GetMapping("/success")
    public ResponseEntity<Void> oauthSuccess(@AuthenticationPrincipal OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String provider = "google";

        ProfileEntity user = profileService.findOrCreateOAuthUser(email, name, provider);
        Map<String, Object> response = profileService.authenticateOAuthUser(user);

        String token = String.valueOf(response.get("token"));
        String redirectUrl = frontendUrl + "/login?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.LOCATION, redirectUrl);
        return ResponseEntity.status(HttpStatus.FOUND).headers(headers).build();
    }

    @GetMapping("/failure")
    public ResponseEntity<String> oauthFailure() {
        return ResponseEntity.badRequest().body("OAuth authentication failed");
    }
}
