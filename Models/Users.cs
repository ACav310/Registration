#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Registration.Models;
public class User
{
    [Key]
    public int UserId { get; set; }
    [Required(ErrorMessage = "First Name is required!")]
    [MinLength(2, ErrorMessage = "First Name must be atleast 2 characters long!")]
    public string FirstName { get; set; } 
    [Required(ErrorMessage = "Last Name is required!")]
    [MinLength(2, ErrorMessage = "Last Name must be atleast 2 characters long!")]
    public string LastName { get; set; } 
    [Required(ErrorMessage ="Email is required!")]
    [EmailAddress]
    public string Email { get; set; }
    [Required(ErrorMessage ="Password is required!")]
    [MinLength(8,ErrorMessage ="Password must be 8 characters long!" )]
    [DataType(DataType.Password)]
    public string Password { get; set; }
    [NotMapped]
    [Required(ErrorMessage ="Confirmation cannot be empty!")]
    [Compare("Password", ErrorMessage ="Confirmation must match Password")]
    [DataType(DataType.Password)]
    public string PassConfirm { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime UpdatedAt { get; set; } = DateTime.Now;
}

