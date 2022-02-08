using ApiSeguridadEmpleados.Models;
using ApiSeguridadEmpleados.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ApiSeguridadEmpleados.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmpleadosController : ControllerBase
    {
        private RepositoryEmpleados repo;

        public EmpleadosController(RepositoryEmpleados repo)
        {
            this.repo = repo;
        }

        [Authorize]
        [HttpGet]
        [Route("[action]")]
        public Empleado PerfilEmpleado()
        {
            //LOS DATOS DEL USUARIO VIENEN EN LOS CLAIMS
            //DE QUIEN SE HA VALIDADO CON EL TOKEN
            List<Claim> claims = HttpContext.User.Claims.ToList();
            //NOSOTROS HEMOS ALMACENADO UNA CLAVE LLAMADA
            //UserData
            string json =
                claims.SingleOrDefault(x => x.Type == "UserData").Value;
            //CONVERTIMOS EL JSON A EMPLEADO
            Empleado empleado = JsonConvert.DeserializeObject<Empleado>(json);
            return empleado;
        }

        [Authorize]
        [HttpGet]
        [Route("[action]")]
        public List<Empleado> Compis()
        {
            List<Claim> claims = HttpContext.User.Claims.ToList();
            string json = claims.SingleOrDefault(z => z.Type == "UserData").Value;
            Empleado empleado = JsonConvert.DeserializeObject<Empleado>(json);
            List<Empleado> empleados = this.repo.GetCompisCurro(empleado.IdDepartamento);

            return empleados;
        }

        
        [HttpGet]
        public List<Empleado> GetEmpleados()
        {
            return this.repo.GetEmpleados();
        }
        [HttpGet("{id}")]
        public Empleado GetEmpleado(int id)
        {
            return this.repo.FindEmpleado(id);
        }

        

    }
}
