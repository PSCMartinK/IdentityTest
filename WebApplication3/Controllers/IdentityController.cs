using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    [Authorize]
    [Route("[controller]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {

        [Route("callback")]
        public string Get() {
            return "hello";
        }

    }
}