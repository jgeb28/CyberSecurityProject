using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class RegisterViewModel
{
    [Required(ErrorMessage = "Username is required")]
    public required string Username { get; init; }
    
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress]
    public required string Email { get; init; }
    
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [Compare("ConfirmPassword", ErrorMessage = "Passwords do not match")]
    public required string Password { get; init; }
    
    [Required(ErrorMessage = "Confirm Password is required")]
    [DataType(DataType.Password)]
    public required string ConfirmPassword { get; init; }
}