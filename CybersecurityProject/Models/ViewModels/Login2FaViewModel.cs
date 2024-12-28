using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class Login2FaViewModel
{
    [Required]
    [RegularExpression(@"^[0-9]+$", ErrorMessage = "Invalid characters in field.")]
    public required string Code { get; init; }
}