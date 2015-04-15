using System.Collections.Generic;
using System.Linq;
using FullOAuth.DAL;
using FullOAuth.DAL.Models;

namespace ConsoleWebApi.DAL
{
    class ClientRepo : IClientRepo
    {
        private static readonly IList<Client> Clients = new List<Client>
        {
            new Client
            {
                Active = true,
                AllowedOrigin = "*",
                ApplicationType = ApplicationTypes.JavaScript,
                RefreshTokenLifeTime = 7200,
                Id = "0"
            }
        };

        public Client FindClient(string clientId)
        {
            return Clients.SingleOrDefault(q => q.Id == clientId);
        }
    }
}
