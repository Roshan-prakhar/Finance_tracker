package in.ROSHAN.moneymanager.service;

import in.ROSHAN.moneymanager.dto.AuthDTO;
import in.ROSHAN.moneymanager.dto.ProfileDTO;
import in.ROSHAN.moneymanager.entity.CategoryEntity;
import in.ROSHAN.moneymanager.entity.ProfileEntity;
import in.ROSHAN.moneymanager.repository.CategoryRepository;
import in.ROSHAN.moneymanager.repository.ProfileRepository;
import in.ROSHAN.moneymanager.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ProfileService {

    private final ProfileRepository profileRepository;
    private final CategoryRepository categoryRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    private static final List<String[]> DEFAULT_CATEGORIES = List.of(
            new String[]{"Salary", "income", "\uD83D\uDCBC"},
            new String[]{"Freelance", "income", "\uD83D\uDCBB"},
            new String[]{"Business", "income", "\uD83C\uDFE2"},
            new String[]{"Investments", "income", "\uD83D\uDCC8"},
            new String[]{"Gifts", "income", "\uD83C\uDF81"},
            new String[]{"Food & Dining", "expense", "\uD83C\uDF7D\uFE0F"},
            new String[]{"Transport", "expense", "\uD83D\uDE97"},
            new String[]{"Housing", "expense", "\uD83C\uDFE0"},
            new String[]{"Utilities", "expense", "\uD83D\uDCA1"},
            new String[]{"Entertainment", "expense", "\uD83C\uDFAC"},
            new String[]{"Healthcare", "expense", "\uD83C\uDFE5"},
            new String[]{"Shopping", "expense", "\uD83D\uDED2"},
            new String[]{"Education", "expense", "\uD83C\uDF93"},
            new String[]{"Travel", "expense", "\u2708\uFE0F"},
            new String[]{"Other", "expense", "\uD83D\uDCCC"}
    );

    private void seedDefaultCategories(ProfileEntity profile) {
        List<CategoryEntity> existing = categoryRepository.findByProfileId(profile.getId());
        if (existing != null && !existing.isEmpty()) return;
        for (String[] c : DEFAULT_CATEGORIES) {
            categoryRepository.save(CategoryEntity.builder()
                    .name(c[0])
                    .type(c[1])
                    .icon(c[2])
                    .profile(profile)
                    .build());
        }
    }

    /**
     * Registers a new profile with default account activation.
     */
    @Transactional
    public ProfileDTO registerProfile(ProfileDTO profileDTO) {
        // Map DTO to Entity and encode the password
        ProfileEntity newProfile = toEntity(profileDTO);
        newProfile.setIsActive(true); // Accounts are activated by default
        newProfile = profileRepository.save(newProfile);
        seedDefaultCategories(newProfile);
        return toDTO(newProfile);
    }

    /**
     * Maps a ProfileDTO object to ProfileEntity.
     */
    public ProfileEntity toEntity(ProfileDTO profileDTO) {
        return ProfileEntity.builder()
                .id(profileDTO.getId())
                .fullName(profileDTO.getFullName())
                .email(profileDTO.getEmail())
                .password(passwordEncoder.encode(profileDTO.getPassword()))
                .profileImageUrl(profileDTO.getProfileImageUrl())
                .createdAt(profileDTO.getCreatedAt())
                .updatedAt(profileDTO.getUpdatedAt())
                .build();
    }

    /**
     * Maps a ProfileEntity object to ProfileDTO.
     */
    public ProfileDTO toDTO(ProfileEntity profileEntity) {
        return ProfileDTO.builder()
                .id(profileEntity.getId())
                .fullName(profileEntity.getFullName())
                .email(profileEntity.getEmail())
                .profileImageUrl(profileEntity.getProfileImageUrl())
                .createdAt(profileEntity.getCreatedAt())
                .updatedAt(profileEntity.getUpdatedAt())
                .build();
    }

    /**
     * Authenticates user credentials and generates a JWT token.
     */
    public Map<String, Object> authenticateAndGenerateToken(AuthDTO authDTO) {
        try {
            // Perform authentication
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authDTO.getEmail(), authDTO.getPassword())
            );
            // Generate JWT for the authenticated user
            String token = jwtUtil.generateToken(authentication.getName());
            return Map.of(
                    "token", token,
                    "user", getPublicProfile(authDTO.getEmail())
            );
        } catch (Exception e) {
            throw new RuntimeException("Invalid email or password", e);
        }
    }

    /**
     * Retrieves the currently authenticated profile entity.
     */
    public ProfileEntity getCurrentProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return profileRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new RuntimeException("Profile not found with email: " + authentication.getName()));
    }

    /**
     * Finds an existing user by email or creates a new one from OAuth2 attributes.
     */
    @Transactional
    public Map<String, Object> findOrCreateOAuthUser(String email, String name, String profileImageUrl) {
        Optional<ProfileEntity> existing = profileRepository.findByEmail(email);
        ProfileEntity profile;
        if (existing.isPresent()) {
            profile = existing.get();
        } else {
            profile = ProfileEntity.builder()
                    .fullName(name)
                    .email(email)
                    .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .profileImageUrl(profileImageUrl)
                    .isActive(true)
                    .build();
            profile = profileRepository.save(profile);
            seedDefaultCategories(profile);
        }
        String token = jwtUtil.generateToken(email);
        return Map.of("token", token, "user", toDTO(profile));
    }

    /**
     * Gets public information of a profile by email.
     */
    public ProfileDTO getPublicProfile(String email) {
        ProfileEntity profile = profileRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Profile not found with email: " + email));
        return toDTO(profile);
    }
}