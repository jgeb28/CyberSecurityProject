using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class ChangePasswordViewModel
{
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public required string OldPassword { get; init; }
    [Required(ErrorMessage = "New Password is required")]
    [DataType(DataType.Password)]
    [Compare("ConfirmPassword", ErrorMessage = "Passwords do not match")]
    public required string NewPassword { get; init; }
    [Required(ErrorMessage = "Confirm Password is required")]
    [DataType(DataType.Password)]
    public required string ConfirmPassword { get; init; }
    [Required]
    [RegularExpression(@"^[0-9]+$", ErrorMessage = "Invalid characters in field.")]
    public required string Code { get; init; }
}