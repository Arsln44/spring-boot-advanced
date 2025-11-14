package sphynx.springbootadvenced.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * AuthenticationManager (Yönetici) Bean'i.
     * Spring Security 6+ ile gelen modern yaklaşım budur.
     * Bu 'AuthenticationConfiguration' nesnesi, Spring'in otomatik olarak
     * bizim DatabaseUserDetailsService'imizi ve PasswordEncoder'ımızı
     * kullanarak oluşturduğu 'Yönetici'yi (AuthenticationManager) barındırır.
     * Biz onu buradan alıp, uygulamanın geri kalanında (örn: AuthController'da)
     * kullanılabilmesi için bir @Bean olarak sunuyoruz.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * SecurityFilterChain (Güvenlik Filtre Zinciri) Bean'i.
     * API'ye gelen tüm isteklerin "kurallarını" tanımladığımız yerdir.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 1. Geleneksel (Stateful) Güvenlik Mekanizmalarını Kapat
        http
                .csrf(csrf -> csrf.disable()) // CSRF'yi kapat (Stateless API'ler için)
                .formLogin(form -> form.disable()) // Varsayılan Form Login sayfasını kapat
                .httpBasic(basic -> basic.disable()); // Varsayılan Basic Auth'u kapat

        // 2. Oturum Yönetimini STATELESS (Durumsuz) Olarak Ayarla
        // BU, JWT KULLANIMI İÇİN ZORUNLUDUR!
        http
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        // 3. İstek İzinlerini (Authorization) Yapılandır
        http
                .authorizeHttpRequests(authz -> authz
                        // Bizim 'login' ve 'register' endpoint'lerimize herkesin erişmesine izin ver
                        .requestMatchers("/api/auth/**").permitAll()

                        // Swagger UI için (Blueprint V1'den hatırlatma)
                        .requestMatchers(
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",       // Ana Swagger UI sayfası
                                "/swagger-resources/**",  // Eski sürüm yönlendirmeleri için
                                "/webjars/**"             // Swagger'ın kullandığı (CSS/JS) statik kaynaklar
                        ).permitAll()

                        // Yukarıdakiler dışındaki DİĞER TÜM istekler
                        .anyRequest().authenticated() // Kimlik doğrulaması (token) gerektirsin
                );

        // (BURAYA DAHA SONRA JWT FİLTREMİZ GELECEK)

        return http.build();
    }
}
