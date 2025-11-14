using JWTPOC.Data;
using JWTPOC.Models;
using JWTPOC.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace JWTPOC.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly TokenService _tokenService;

    public AuthController(AppDbContext context, TokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [HttpPost("register")]
    public async Task<ActionResult<string>> Register(Register request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            return BadRequest($"Registration failed: username '{request.Username}' is already taken.");

        var user = new User
        {
            Username = request.Username,
            PasswordHash = HashPassword(request.Password),
            Email = request.Email,
            MobileNumber = request.MobileNumber,
            City = request.City
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok($"User '{request.Username}' registered successfully.");
    }



    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login(Login request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
            return Unauthorized($"Login failed: invalid credentials for '{request.Username}'.");

        var accessToken = _tokenService.GenerateAccessToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken();

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _context.SaveChangesAsync();

        return Ok(new TokenResponse
        {
            JwtAccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }


    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh(TokenResponse tokenModel)
    {
        var principal = _tokenService.GetPrincipalFromExpiredToken(tokenModel.JwtAccessToken);
        if (principal == null)
            return BadRequest("Token refresh failed: access token is invalid or malformed.");

        var username = principal.Identity?.Name;
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            return Unauthorized($"Token refresh failed: refresh token is invalid or expired for user '{username}'.");

        var newAccessToken = _tokenService.GenerateAccessToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _context.SaveChangesAsync();

        return Ok(new TokenResponse
        {
            JwtAccessToken = newAccessToken,
            RefreshToken = newRefreshToken
        });
    }

    [Authorize]
    [HttpGet("protected")]
    public ActionResult<string> Protected()
    {
        return Ok($"Access granted: welcome '{User.Identity?.Name}', you reached a protected endpoint.");
    }

    // Hash password using SHA256
    private static string HashPassword(string password)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    // Verify password against stored hash
    private static bool VerifyPassword(string password, string hash)
    {
        return HashPassword(password) == hash;
    }
}
