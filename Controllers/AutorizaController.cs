using ApiDapperIdentity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;

namespace ApiDapperIdentity.Controllers
{
    [Route("api/[Controller]")]
    [ApiController]
    public class AutorizaController : ControllerBase
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AutorizaController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpGet]
        public ActionResult<string> Get()
        {
            return "AutorizaController :: Acessado em : " + DateTime.Now.ToLongTimeString();
        }

        [HttpPost("registro")]
        public async Task<ActionResult> RegistraUsuario([FromBody] Usuario usuario)
        {
            try
            {



                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(x => x.Errors));
                }

                var user = new ApplicationUser
                {
                    UserName = usuario.Nome,
                    Email = usuario.Email,
                    EmailConfirmed = true
                };

                var result = await _userManager.CreateAsync(user, usuario.Senha);
                await _signInManager.SignInAsync(user, isPersistent: false);

                if (!result.Succeeded)
                {
                    return BadRequest(result.Errors);
                }

                await _signInManager.SignInAsync(user, false);

                return Ok(GeraToken(usuario));
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult> Login([FromBody] Usuario usuario)
        {
            try
            {


                //verifica se o modelo é válido
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState.Values.SelectMany(x => x.Errors));
                }

                //verifica as credenciais do usuário e retorna um valor
                var result = await _signInManager.PasswordSignInAsync(usuario.Nome, usuario.Senha, isPersistent: false, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    return Ok(GeraToken(usuario));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Login Inválido...");
                    return BadRequest(ModelState);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        //Metodo para gerar o token
        private UsuarioToken GeraToken(Usuario usuario)
        {
            //define declarações do usuário
            var claims = new[]
            {
                 new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.UniqueName, usuario.Email),
                new Claim("meuPet","Pipoca"),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //gera uma chave com base em um algoritmo simetrico
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            //gera a assinatura digital do token usando o algoritmo HMAC e a chave privada

            var credenciais = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //Tempo de expiração do token
            var expiracao = _configuration["TokenConfiguration:ExpireHours"];
            var expiration = DateTime.UtcNow.AddHours(double.Parse(expiracao));

            //classe que representa um token JWT e gera o token
            JwtSecurityToken token = new JwtSecurityToken(
                issuer: _configuration["TokenConfiguration:Issuer"],
                audience: _configuration["TokenConfiguration:Audience"],
                claims: claims,
                expires: expiration,
                signingCredentials: credenciais);

            //retorna os dados com o token e informacoes
            return new UsuarioToken()
            {
                Authenticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = expiration,
                Message = "Json Web Token"
            };
        }

    }
}
