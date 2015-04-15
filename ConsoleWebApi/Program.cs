using System;
using Microsoft.Owin.Hosting;

namespace ConsoleWebApi
{
    class Program
    {
        static void Main(string[] args)
        {
            using (WebApp.Start<Startup>("http://localhost:9000/"))
            {
                Console.WriteLine("Press enter to exit...");
                Console.ReadLine();
            }
        }
    }
}
