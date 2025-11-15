package sphynx.springbootadvenced.auth;

public record LoginRequest(
        String username,
        String password
) {
}
