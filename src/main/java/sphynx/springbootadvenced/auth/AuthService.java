package sphynx.springbootadvenced.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import sphynx.springbootadvenced.security.JwtService;
import sphynx.springbootadvenced.user.User;
import sphynx.springbootadvenced.user.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Yeni bir kullanıcıyı sisteme kaydeder.
     *
     * @param registerRequest Kayıt için gerekli bilgileri (username, password) içeren DTO.
     * @return Başarılı kayıt sonrası oluşturulan JWT'yi içeren AuthResponse.
     */

    public AuthResponse register(RegisterRequest registerRequest) {
        // 1. Yeni User nesnesini @Builder ile temiz bir şekilde oluştur
        var user = User.builder()
                .username(registerRequest.username())
                // ŞİFRE KRİTİK: Şifreyi ASLA düz metin kaydetme.
                // SecurityConfig'de tanımladığımız PasswordEncoder ile hash'le
                .password(passwordEncoder.encode(registerRequest.password()))
                // Şimdilik her yeni kullanıcıya "USER" rolü veriyoruz.
                // Gelişmiş sistemlerde bu da dinamik olabilir.
                .role("ROLE_USER")
                .build();

        // 2. Kullanıcıyı veritabanına kaydet
        // (Not: Gelişmiş sistemde burada 'username' zaten var mı diye
        // 'userRepository.findByUsername' ile kontrol etmek gerekir.)
        userRepository.save(user);

        // 3. Yeni kullanıcı için bir JWT üret
        var jwtToken = jwtService.generateToken(user);

        // 4. Token'ı AuthResponse DTO'su (record) içinde döndür
        return new AuthResponse(jwtToken);
    }

    /**
     * Mevcut bir kullanıcının sisteme giriş yapmasını sağlar.
     *
     * @param loginRequest Giriş için gerekli bilgileri (username, password) içeren DTO.
     * @return Başarılı giriş sonrası oluşturulan JWT'yi içeren AuthResponse.
     */
    public AuthResponse login(LoginRequest loginRequest) {
        // 1. KİMLİK DOĞRULAMA (Authentication)
        // Bu, Aşama 10.3B'de @Bean yaptığımız 'AuthenticationManager'ı kullanır.
        // Spring Security'ye diyoruz ki:
        // "Al bu kullanıcı adı ve şifreyi (Token olarak),
        // benim DatabaseUserDetailsService'imi ve PasswordEncoder'ımı kullanarak
        // bu kişinin kimliğini doğrula."
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.username(),
                        loginRequest.password()
                )
        );
        // ÖNEMLİ NOT: Eğer kimlik doğrulama başarısız olursa
        // (şifre yanlışsa veya kullanıcı yoksa), 'authenticate' metodu
        // otomatik olarak bir 'AuthenticationException' fırlatır ve
        // bu metot burada durur (aşağıdaki kod çalışmaz).

        // 2. KULLANICIYI BUL (Token Üretmek İçin)
        // Kimlik doğrulama başarılıysa (yani kod buraya ulaştıysa),
        // token üretmek için kullanıcı bilgilerine ihtiyacımız var.
        // Veritabanından kullanıcıyı tekrar çekiyoruz.
        var user = userRepository.findByUsername(loginRequest.username())
                .orElseThrow(() -> new IllegalArgumentException("Kullanıcı doğrulandı ama veritabanında bulunamadı."));
        // (Bu .orElseThrow normalde olmamalı, çünkü 'authenticate' başarılı olduysa
        // kullanıcı %100 vardır. Bu sadece bir güvenlik önlemidir.)

        // 3. YENİ JWT ÜRET
        var jwtToken = jwtService.generateToken(user);

        // 4. Token'ı döndür
        return new AuthResponse(jwtToken);
    }
}
