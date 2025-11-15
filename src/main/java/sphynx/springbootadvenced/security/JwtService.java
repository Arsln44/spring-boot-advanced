package sphynx.springbootadvenced.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JWT (JSON Web Token) üretme, doğrulama ve ayrıştırma (parse)
 * işlemlerinden sorumlu "Çilingir" servisidir.
 *
 * Bu servis, kriptografi mantığını projenin geri kalanından soyutlar.
 */
@Service
public class JwtService {

    private final String jwtSecretKey;
    private final long jwtExpirationMs;

    /**
     * Servisin constructor'ı.
     * Gizli anahtarı ve geçerlilik süresini application.properties dosyasından
     * @Value anotasyonu ile güvenli bir şekilde enjekte eder.
     */
    public JwtService(
            @Value("${jwt.secret-key}") String jwtSecretKey,
            @Value("${jwt.expiration-ms}") long jwtExpirationMs) {
        this.jwtSecretKey = jwtSecretKey;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    // =================================================================================
    // PUBLIC METOTLAR (Dış Dünyanın Kullanacağı Arayüz)
    // =================================================================================

    /**
     * Verilen bir token'ın içinden kullanıcı adını (subject) çıkarır.
     *
     * @param token Geçerli JWT
     * @return Kullanıcı adı (username)
     */
    public String extractUsername(String token) {
        // Claims::getSubject -> 'subject' (konu) alanını al demektir.
        // Biz 'subject' alanına kullanıcı adını kaydedeceğiz.
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Sadece UserDetails kullanarak yeni bir JWT üretir (ekstra 'claim' olmadan).
     *
     * @param userDetails Token'ın sahibi olan kullanıcı
     * @return İmzalı JWT String'i
     */
    public String generateToken(UserDetails userDetails) {
        // Ekstra 'claim' (iddia) olmadan, boş bir Map ile ana metodu çağırır.
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Verilen UserDetails ve ekstra 'claim'ler (örn: roller, isim vb.)
     * ile yeni bir JWT üretir.
     *
     * @param extraClaims Token'ın 'payload' kısmına eklenecek ekstra bilgiler.
     * @param userDetails Token'ın sahibi olan kullanıcı.
     * @return İmzalı JWT String'i
     */
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts.builder()
                .setClaims(extraClaims) // Ekstra bilgileri ekle
                .setSubject(userDetails.getUsername()) // Token'ın konusunu (sahibini) ayarla
                .setIssuedAt(new Date(System.currentTimeMillis())) // Başlangıç zamanı (şimdi)
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs)) // Bitiş zamanı
                .signWith(getSignInKey(), SignatureAlgorithm.HS512) // İmza algoritması ve anahtar
                .compact(); // Token'ı oluştur ve String'e çevir
    }

    /**
     * Bir token'ın geçerli olup olmadığını kontrol eder.
     * Ana doğrulama metodu budur.
     *
     * @param token       Kontrol edilecek JWT
     * @param userDetails Veritabanından gelen kullanıcı bilgisi
     * @return true (geçerliyse) / false (geçersizse)
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token); // Token'dan kullanıcı adını al
        // 1. Token'daki kullanıcı adı ile veritabanındaki kullanıcı adı eşleşiyor mu?
        // 2. Token'ın süresi dolmuş mu?
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // =================================================================================
    // PRIVATE METOTLAR (Sadece Bu Sınıfın İç İhtiyaçları)
    // =================================================================================

    /**
     * Token'ın süresinin dolup dolmadığını kontrol eder.
     *
     * @param token Kontrol edilecek JWT
     * @return true (süresi dolmuşsa) / false (hala geçerliyse)
     */
    private boolean isTokenExpired(String token) {
        // Token'ın son kullanma tarihini al ve 'şimdi'den önce mi diye kontrol et.
        return extractExpiration(token).before(new Date());
    }

    /**
     * Token'dan 'expiration' (son kullanma) tarihini çıkarır.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Gelen bir token'ı "açar" (parse eder) ve içindeki tüm 'Claim'leri
     * (iddiaları/payload'u) okur.
     *
     * BU METOT, İMZAYI (Signature) DOĞRULAYAN ANA METOTTUR.
     * İmza geçersizse veya token bozuksa, burada bir Exception fırlatır.
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) // Doğrulama için anahtarı ayarla
                .build()
                .parseClaimsJws(token) // Token'ı ayrıştır ve doğrula
                .getBody(); // İçeriği (payload) al
    }

    /**
     * Token'dan belirli bir 'Claim'i (iddia) çıkarmak için kullanılan
     * genel (generic) yardımcı metot.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 'application.properties' dosyasındaki Base64 formatındaki gizli anahtarımızı (String)
     * alıp, kriptografik imzalama için uygun bir 'Key' nesnesine dönüştürür.
     *
     * BU, GÜVENLİĞİN EN KRİTİK NOKTASIDIR.
     */
    private Key getSignInKey() {
        // 1. Base64 String'i byte dizisine çöz (decode)
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecretKey);
        // 2. Bu byte dizisini HMAC-SHA algoritması için bir 'Key' nesnesine dönüştür
        return Keys.hmacShaKeyFor(keyBytes);
    }
}