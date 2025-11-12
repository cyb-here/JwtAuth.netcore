namespace JWTPOC.Models;

public class TokenResponse
{
    public string JwtAccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
}
