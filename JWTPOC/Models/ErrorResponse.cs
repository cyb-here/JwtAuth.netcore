namespace JWTPOC.Models;

/// <summary>
/// Standardized error response returned by controllers and middleware.
/// </summary>
public class ErrorResponse
{
    public int StatusCode { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? Detailed { get; set; } // optional, for dev/debug
    public string TraceId { get; set; } = string.Empty; // useful for log correlation
}
