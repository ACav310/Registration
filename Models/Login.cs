#pragma warning disable CS8618
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Registration.Models;
public class Login
{
    [Required(ErrorMessage ="Email is required!")]
    [EmailAddress]
    public string LEmail { get; set; }
    [Required(ErrorMessage ="Password is required!")]
    [MinLength(8,ErrorMessage ="Password must be 8 characters long!" )]
    [DataType(DataType.Password)]
    public string LPassword { get; set; }
}