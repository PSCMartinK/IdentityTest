using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace WebApplication1.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        [HttpGet]
        public string Index()
        {
            return $"Hi there, {this.User?.Identity.Name}";
        }

        [HttpGet("Claims")]
        public IEnumerable<string> Claims()
        {
            var claims = this.User.Claims.Select(c => $"{c.Type} = {c.Value}");
            return claims;
        }
    }
}
