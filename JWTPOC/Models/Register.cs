using System.ComponentModel.DataAnnotations;

namespace JWTPOC.Models;

public class Register
{
    [Required(ErrorMessage = "Username is required.")]
    [StringLength(50, MinimumLength = 2, ErrorMessage = "Username must be between 2 and 50 characters.")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required.")]
    [StringLength(100, MinimumLength = 4, ErrorMessage = "Password must be at least 4 characters.")]
    public string Password { get; set; } = string.Empty;
}
