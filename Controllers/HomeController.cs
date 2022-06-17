using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Registration.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;

namespace Registration.Controllers;

public class HomeController : Controller
{
    private MyContext _context;
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger, MyContext context)
    {
        _logger = logger;
        _context = context;
    }

    public IActionResult Index()
    {
        HttpContext.Session.Clear();
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [HttpPost("/user/register")]
    public IActionResult Register(User newUser)
    {            
    
        if(ModelState.IsValid)
        {  
            // need to check if email is unique
            if (_context.Users.Any(a => a.Email == newUser.Email))
            {
                //email already exist
                ModelState.AddModelError("Email", "Email is already in use!");
                return View("Index");
            }
            PasswordHasher<User> Hasher = new PasswordHasher<User>();
            newUser.Password = Hasher.HashPassword(newUser, newUser.Password);
            _context.Add(newUser);
            _context.SaveChanges();
            HttpContext.Session.SetInt32("user", newUser.UserId);
            return RedirectToAction("Success");
        } else {
            return View("Index");
        }
    }

    [HttpGet("success")]
    public IActionResult Success()
    {
        User loggedInUser = _context.Users.FirstOrDefault(a=> a.UserId == HttpContext.Session.GetInt32("user"));
        return View(loggedInUser);
    }

    [HttpGet("Login")]
    public IActionResult Login()
    {
        return View();
    }


    [HttpPost("user/login")]
    public IActionResult Login(Login LoginUser)
    {
        if (ModelState.IsValid)
        {   // find their email in the database to make sure email matches password
            User userInDb = _context.Users.FirstOrDefault(a=> a.Email == LoginUser.LEmail);
            if(userInDb == null)
            {
                // no email matching in db
                ModelState.AddModelError("LEmail", "Invalid Login Attempt");
                return View("Login");
            }
            PasswordHasher<Login> hasher = new PasswordHasher<Login>();
            var result = hasher.VerifyHashedPassword(LoginUser, userInDb.Password, LoginUser.LPassword);
            if (result == 0)
            {
                ModelState.AddModelError("LEmail", "Invalid Login Attempt");
                return View("Login");
            } else {
                HttpContext.Session.SetInt32("user", userInDb.UserId);
                return RedirectToAction("Success");
            }
        } else {
            return View("Login");
        }
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
