using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebApiOAuthTest
{
    public class ExternalLoginViewModel
    {
        public string Name { get; set; }

        public string Url { get; set; }

        public string State { get; set; }
    }

    public class RegisterExternalBindingModel
    {
        public string UserName { get; set; }

        public string Provider { get; set; }

        public string ExternalAccessToken { get; set; }

    }

    public class ParsedExternalAccessToken
    {
        public string UserId { get; set; }
        public string AppId { get; set; }
    }
}
