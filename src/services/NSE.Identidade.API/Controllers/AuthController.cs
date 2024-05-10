using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NSE.Identidade.API.Models;
using System.Threading.Tasks;

namespace NSE.Identidade.API.Controllers
{
    [Route("api/identidade")]
    public class AuthController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _UserManager;

        public AuthController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
        {
            _signInManager = signInManager;
            _UserManager = userManager;
        }

        [HttpPost("nova-conta")]
        public async Task<ActionResult> Registrar(UsuarioRegistro registro)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var user = new IdentityUser
            {
                UserName = registro.Email,
                Email = registro.Email,
                EmailConfirmed = true
            };

            var result = await _UserManager.CreateAsync(user, registro.Senha);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return Ok();
            }

            return BadRequest();
        }

        [HttpPost("autenticar")]
        public async Task<ActionResult> Login(UsuarioLogin login)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var result = await _signInManager.PasswordSignInAsync(login.Email, login.Senha, false, true);

            if (result.Succeeded)
            {
                return Ok();
            }
            return BadRequest();

        }
    }
}
