using System.Web.Http;
using ConsoleWebApi.DAL;

namespace ConsoleWebApi.Controllers
{
    public class RegisterController : ApiController
    {
        public IHttpActionResult Post(string userName, string password)
        {
            UserRepo.RegisterUser(userName, password);

            return Ok();
        }
    }
}