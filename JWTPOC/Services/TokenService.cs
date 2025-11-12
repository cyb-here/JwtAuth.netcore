using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JWTPOC.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWTPOC.Services;

/// Handles JWT access token generation, refresh token creation, and token validation.
public class TokenService
{
    private readonly IConfiguration _config;

    /// Injects configuration to access JWT settings from appsettings.json.
    public TokenService(IConfiguration config)
    {
        _config = config;
    }

    /// Generates a signed JWT access token for the authenticated user.
    /// <param name="user">Authenticated user object</param>
    /// <returns>JWT access token string</returns>
    public string GenerateAccessToken(User user)
    {
        // Define claims embedded in the token
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Username), // Used for identity
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Unique token ID
        };

        // Create a symmetric key from the configured secret
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Secret"]!));

        // Sign the token using HMAC SHA256
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Create the token with issuer, audience, claims, expiry, and signing credentials
        var token = new JwtSecurityToken(
            issuer: _config["JWT:ValidIssuer"],
            audience: _config["JWT:ValidAudience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(15), // Token validity
            signingCredentials: creds
        );

        // Serialize and return the token string
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// Generates a secure random refresh token.
    /// <returns>Base64-encoded refresh token</returns>
    public string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];

        // Use cryptographically secure RNG
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        // Return as Base64 string
        return Convert.ToBase64String(randomBytes);
    }

    /// Extracts claims from an expired access token for refresh validation.
    /// <param name="token">Expired JWT access token</param>
    /// <returns>ClaimsPrincipal if valid, null if invalid</returns>
    public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
    {
        // Configure token validation parameters
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = false, // Ignore expiry for refresh flow
            ValidIssuer = _config["JWT:ValidIssuer"],
            ValidAudience = _config["JWT:ValidAudience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Secret"]!))
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        // Validate token and extract principal
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

        // Ensure token is a valid JWT and signed with expected algorithm
        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }
}
