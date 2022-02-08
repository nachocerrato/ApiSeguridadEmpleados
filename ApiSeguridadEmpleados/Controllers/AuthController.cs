using ApiSeguridadEmpleados.Helpers;
using ApiSeguridadEmpleados.Models;
using ApiSeguridadEmpleados.Repositories;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ApiSeguridadEmpleados.Controllers
{
    //https://servicioempleadosapi/auth
    [Route("Auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private RepositoryEmpleados repo;
        private HelperOAuthToken helper;

        public AuthController(RepositoryEmpleados repo, IConfiguration configuration)
        {
            this.repo = repo;
            this.helper = new HelperOAuthToken(configuration);
        }

        //Necesitamos un método para realizar la validación, los endpoint de 
        //OAuth son post
        //Recibiremos el LoginModel
        [HttpPost]
        [Route("[action]")]
        public IActionResult Login(LoginModel model)
        {
            //Vamos a validar directamente con empleados
            Empleado empleado =
                this.repo.ExisteEmpleado(model.UserName, int.Parse(model.Password));

            if(empleado == null)
            {
                return Unauthorized();
            }
            else
            {
                //Almacenamos el dato del empleado validad dentro del token
                string jsonempleado =
                    JsonConvert.SerializeObject(empleado);
                //Los claims van en array o colección
                Claim[] claims = new[]
                {
                    new Claim("UserData",jsonempleado)
                };


                //Un Token lleva unas credenciales
                SigningCredentials credentials =
                    new SigningCredentials(this.helper.GetKeyToken(),
                    SecurityAlgorithms.HmacSha256);
                //Necesitamos generar un token
                //El token puede llevar información del tipo Issuer, Duracion, Credenciales de Usuario
                JwtSecurityToken token =
                    new JwtSecurityToken(
                        claims: claims,
                        issuer: this.helper.Issuer,
                        audience: this.helper.Audience,
                        expires: DateTime.UtcNow.AddMinutes(10),
                        notBefore: DateTime.UtcNow,
                        signingCredentials: credentials);
                //Devolvemos una respuesta correcta con el token
                return Ok(
                    new
                    {
                        response =
                        new JwtSecurityTokenHandler().WriteToken(token)
                    });
            }
        }


    }
}
