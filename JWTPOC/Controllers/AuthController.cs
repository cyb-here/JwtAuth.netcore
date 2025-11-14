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

    /// <summary>
    /// Injects database context and token service via dependency injection.
    /// </summary>
    public AuthController(AppDbContext context, TokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    /// <summary>
    /// Registers a new user with username, password, email, mobile number, and city.
    /// - Validates input using data annotations.
    /// - Ensures username is unique.
    /// - Hashes password before storing.
    /// </summary>
    /// <param name="request">Registration request containing user details.</param>
    /// <returns>Success message or validation error.</returns>
    [HttpPost("register")]
    public async Task<ActionResult<string>> Register(Register request)
    {
        // Validate model state (checks data annotations in Register.cs)
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        // Ensure username is unique
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            return BadRequest($"Registration failed: username '{request.Username}' is already taken.");

        // Create new user entity with hashed password
        var user = new User
        {
            Username = request.Username,
            PasswordHash = HashPassword(request.Password),
            Email = request.Email,
            MobileNumber = request.MobileNumber,
            City = request.City
        };

        // Save user to database
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok($"User '{request.Username}' registered successfully.");
    }

    /// <summary>
    /// Authenticates a user and issues JWT access + refresh tokens.
    /// - Validates credentials against stored hash.
    /// - Generates short-lived access token and long-lived refresh token.
    /// - Persists refresh token in database for future validation.
    /// </summary>
    /// <param name="request">Login request containing username and password.</param>
    /// <returns>TokenResponse with access and refresh tokens.</returns>
    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login(Login request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        // Find user by username
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

        // Validate credentials
        if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
            return Unauthorized($"Login failed: invalid credentials for '{request.Username}'.");

        // Generate tokens
        var accessToken = _tokenService.GenerateAccessToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // Store refresh token and expiry in DB
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _context.SaveChangesAsync();

        // Return tokens to client
        return Ok(new TokenResponse
        {
            JwtAccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }

    /// <summary>
    /// Refreshes expired access tokens using a valid refresh token.
    /// - Extracts claims from expired access token.
    /// - Validates refresh token against DB and expiry.
    /// - Issues new access + refresh tokens.
    /// </summary>
    /// <param name="tokenModel">TokenResponse containing expired access token and refresh token.</param>
    /// <returns>New TokenResponse with fresh tokens.</returns>
    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh(TokenResponse tokenModel)
    {
        // Extract principal from expired access token (ignores lifetime)
        var principal = _tokenService.GetPrincipalFromExpiredToken(tokenModel.JwtAccessToken);
        if (principal == null)
            return BadRequest("Token refresh failed: access token is invalid or malformed.");

        var username = principal.Identity?.Name;

        // Validate refresh token against DB record
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            return Unauthorized($"Token refresh failed: refresh token is invalid or expired for user '{username}'.");

        // Generate new tokens
        var newAccessToken = _tokenService.GenerateAccessToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        // Rotate refresh token (replace old with new)
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _context.SaveChangesAsync();

        return Ok(new TokenResponse
        {
            JwtAccessToken = newAccessToken,
            RefreshToken = newRefreshToken
        });
    }

    /// <summary>
    /// Example protected endpoint.
    /// - Requires valid JWT access token in Authorization header.
    /// - Returns a message with the authenticated username.
    /// </summary>
    [Authorize]
    [HttpGet("protected")]
    public ActionResult<string> Protected()
    {
        return Ok($"Access granted: welcome '{User.Identity?.Name}', you reached a protected endpoint.");
    }

    /// <summary>
    /// Hashes a plain-text password using SHA256.
    /// </summary>
    private static string HashPassword(string password)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Verifies a plain-text password against a stored hash.
    /// </summary>
    private static bool VerifyPassword(string password, string hash)
    {
        return HashPassword(password) == hash;
    }
}
