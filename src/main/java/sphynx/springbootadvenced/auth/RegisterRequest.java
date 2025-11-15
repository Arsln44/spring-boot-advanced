package sphynx.springbootadvenced.auth;

public record RegisterRequest(
        String username,
        String password
) {
}
