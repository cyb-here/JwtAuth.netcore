using JWTPOC.Data;
using JWTPOC.Models;
using JWTPOC.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace JWTPOC.Controllers;

/// <summary>
/// Authentication controller handling user registration, login, token refresh, and protected endpoints.
/// </summary>
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

    [HttpPost("register")]
    public async Task<ActionResult> Register(Register request)
    {
        // Updated: return unified ErrorResponse instead of raw ModelState
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                StatusCode = 400,
                Message = "Validation failed.",
                Detailed = string.Join("; ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)),
                TraceId = HttpContext.TraceIdentifier
            });
        }

        // 🔄 Updated: return unified ErrorResponse instead of plain string
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
        {
            return BadRequest(new ErrorResponse
            {
                StatusCode = 400,
                Message = $"Registration failed: username '{request.Username}' is already taken.",
                TraceId = HttpContext.TraceIdentifier
            });
        }

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

        // 🔄 Updated: wrap success response in JSON object for consistency
        return Ok(new { Message = $"User '{request.Username}' registered successfully." });
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login(Login request)
    {
        // 🔄 Updated: return unified ErrorResponse instead of raw ModelState
        if (!ModelState.IsValid)
        {
            return BadRequest(new ErrorResponse
            {
                StatusCode = 400,
                Message = "Validation failed.",
                Detailed = string.Join("; ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)),
                TraceId = HttpContext.TraceIdentifier
            });
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

        // 🔄 Updated: return unified ErrorResponse instead of plain Unauthorized string
        if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
        {
            return Unauthorized(new ErrorResponse
            {
                StatusCode = 401,
                Message = $"Login failed: invalid credentials for user'{request.Username}'.",
                TraceId = HttpContext.TraceIdentifier
            });
        }

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
        // 🔄 Updated: return unified ErrorResponse instead of plain BadRequest string
        var principal = _tokenService.GetPrincipalFromExpiredToken(tokenModel.JwtAccessToken);
        if (principal == null)
        {
            return BadRequest(new ErrorResponse
            {
                StatusCode = 400,
                Message = "Token refresh failed: access token is invalid or malformed.",
                TraceId = HttpContext.TraceIdentifier
            });
        }

        var username = principal.Identity?.Name;
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

        // 🔄 Updated: return unified ErrorResponse instead of plain Unauthorized string
        if (user == null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return Unauthorized(new ErrorResponse
            {
                StatusCode = 401,
                Message = $"Token refresh failed: refresh token is invalid or expired for user '{username}'.",
                TraceId = HttpContext.TraceIdentifier
            });
        }

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

    private static string HashPassword(string password)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    private static bool VerifyPassword(string password, string hash)
    {
        return HashPassword(password) == hash;
    }
}
