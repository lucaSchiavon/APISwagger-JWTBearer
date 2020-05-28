using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using WebApiNetCore.Modelli;

namespace WebApiNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;
        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        //prende le credenziali di login e se le credenziali sono valide ossia userid e pwd trovano riscontro nel database
        //con i dati dell'utente viene generato un token
        public IActionResult Login(string username, string pass)
        {
            UserModel login = new UserModel();
            login.UserName = username;
            login.Password = pass;
            IActionResult reponse = Unauthorized();

            var user = AuthenticateUser(login);
            if (user != null)
            {
                //se le credenziali di accesso sono corrette genero il token
                var tokenStr = GenerateJSONWebToken(user);
                reponse = Ok(new {token= tokenStr });
            }
            return reponse;
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;
            //qui va a vedere nel db se esiste un username con userid e password
            if (login.UserName == "ashproghelp" && login.Password == "123")
            {
                user = new UserModel { UserName = "ashproghelp", EmailAddress = "ashproghelp@gmail.com", Password = "123" };
            }

            return user;
        }

       
        private string GenerateJSONWebToken(UserModel userinfo)
        {
            //installare qui pacchetto nuget microsoft.identity.model.tokens

            //la chiave dell'appsetting  viene codificata in binario
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            //la chiave dell'appsetting  viene passata a SigningCredentials per ottenere delle credenziali
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            //crea i JWT claims
            var claims = new[]
            { 
                //qui installare pacchetto nuget system.identitymodel.token.jwt
            new Claim(JwtRegisteredClaimNames.Sub,userinfo.UserName),
             new Claim(JwtRegisteredClaimNames.Email,userinfo.EmailAddress),
              new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };

            //e successivamente si crea il jwt Token
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
               claims,
               expires: DateTime.Now.AddMinutes(120),
               signingCredentials: credentials
                );
            //il token viene passato all'handler di gestione....
            var encodetoken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodetoken;
        }

        [Authorize]
        [HttpPost("Post")]
        public string Post()
        {
            //recupero i claims qui
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claim = identity.Claims.ToList();
            var userName = claim[0].Value;
            return "Welcome To: " + userName;
        }

        [Authorize]
        [HttpGet("GetValue")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }
    }
}