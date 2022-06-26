using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using AppAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace AppAuth.Controllers;

public class AccountController : Controller
{

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Login(string username, string password)
    {
        if (username == "admin" && password == "admin")
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier,username),
                new Claim(ClaimTypes.Role,"admin"),
                new Claim("Test Claim","Test Claim")
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var pricipal = new ClaimsPrincipal(identity);

            HttpContext.SignInAsync(pricipal);
            return RedirectToAction("Index", "Home");
        }
        return Unauthorized();
    }

    public IActionResult Logout()
    {
        HttpContext.SignOutAsync();
        return RedirectToAction("Login", "Account");
    }
}