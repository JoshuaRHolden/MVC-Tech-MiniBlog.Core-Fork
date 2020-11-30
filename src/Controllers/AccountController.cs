using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Miniblog.Core.Models;
using System.Security.Claims;
using System.Threading.Tasks;
using Miniblog.Core.Services;
using System.Collections.Generic;

namespace Miniblog.Core.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly IUserServices _userServices;
        private readonly IBlogService _blog;

        public AccountController(IUserServices userServices, IBlogService blog)
        {
            _userServices = userServices;
            _blog = blog;
        }


        [Route("/login")]
        [AllowAnonymous]
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            ViewData["AllCategories"] = new List<string>() { };
            
            return View();
        }

        [Route("/login")]
        [HttpPost, AllowAnonymous, ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginAsync(string returnUrl, LoginViewModel model)
        {
            ViewData["ReturnUrl"] = returnUrl;
            ViewData["AllCategories"] = new List<string>() { };
            if (ModelState.IsValid && _userServices.ValidateUser(model.UserName, model.Password))
            {
                var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
                identity.AddClaim(new Claim(ClaimTypes.Name, model.UserName));

                var principle = new ClaimsPrincipal(identity);
                var properties = new AuthenticationProperties {IsPersistent = model.RememberMe};
                await HttpContext.SignInAsync(principle, properties);

                return LocalRedirect(returnUrl ?? "/");
            }

            ModelState.AddModelError(string.Empty, "Username or password is invalid.");
            return View("Login", model);
        }

        [Route("/logout")]
        public async Task<IActionResult> LogOutAsync()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return LocalRedirect("/");
        }
    }
}
