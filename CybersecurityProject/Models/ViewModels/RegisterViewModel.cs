using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class RegisterViewModel
{
    [Required(ErrorMessage = "Username is required")]
    [RegularExpression(@"^[a-zA-Z0-9@._-]+$", ErrorMessage = "Invalid characters in field.")]
    public required string Username { get; set; }
    
    [Required(ErrorMessage = "Email is required")]
    [RegularExpression(@"^[a-zA-Z0-9@._-]+$", ErrorMessage = "Invalid characters in field.")]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [RegularExpression(@"^[a-zA-Z0-9@._-]+$", ErrorMessage = "Invalid characters in field.")]
    [Compare("ConfirmPassword", ErrorMessage = "Passwords do not match")]
    public required string Password { get; set; }
    
    [Required(ErrorMessage = "Confirm Password is required")]
    [RegularExpression(@"^[a-zA-Z0-9@._-]+$", ErrorMessage = "Invalid characters in field.")]
    [DataType(DataType.Password)]
    public required string ConfirmPassword { get; set; }
}