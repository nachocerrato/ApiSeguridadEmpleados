using ApiSeguridadEmpleados.Data;
using ApiSeguridadEmpleados.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiSeguridadEmpleados.Repositories
{
    public class RepositoryEmpleados
    {
        private EmpleadosContext context;
        public RepositoryEmpleados(EmpleadosContext context)
        {
            this.context = context;
        }

        public List<Empleado> GetEmpleados()
        {
            return this.context.Empleados.ToList();
        }

        public Empleado FindEmpleado(int idempleado)
        {
            return this.context.Empleados
                .SingleOrDefault(x => x.IdEmpleado == idempleado);
        }

        public Empleado ExisteEmpleado(string apellido, int empno)
        {
            var consulta = from datos in this.context.Empleados
                           where datos.Apellido == apellido
                           && datos.IdEmpleado == empno
                           select datos;
            return consulta.FirstOrDefault();
        }

        public List<Empleado> GetCompisCurro(int iddepartamento)
        {
            var consulta = from datos in this.context.Empleados
                           where datos.IdDepartamento == iddepartamento
                           select datos;
            return consulta.ToList();
        }
    }
}
