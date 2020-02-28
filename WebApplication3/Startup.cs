using IdentityModel;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace WebApplication3
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.Authority = Configuration["Identity:Domain"];
                options.RequireHttpsMetadata = true;
                options.ClientId = Configuration["Identity:ClientId"];
                options.ClientSecret = Configuration["Identity:ClientSecret"];
                options.ResponseType = OpenIdConnectResponseType.Code; // OpenIdConnectResponseType.Code;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Clear(); // Cleam them all before we start as it defaults to "openid profile"
                options.Scope.Add("openid email profile");
                options.SaveTokens = true;
                //options.UsePkce = true; // If not using .Net Core 3 this is a real Pain!
                //options.Events.OnRedirectToIdentityProvider = async n =>
                //{
                //    n.ProtocolMessage.RedirectUri = "http://localhost:4242/identity/callback";
                //    await Task.FromResult(0);
                //};

                // use helper methods for the IdentityModel library to help
                // with common functionality such as random value generation and Base64 URL encoding
                // To make an authorization request that uses PKCE,
                // the authorization request has to include a code_challenge.
                // Create code_verifier value, hash it, and add it to the authorization request.
                options.Events.OnRedirectToIdentityProvider = context =>
                {
                    // only modify requests to the authorization endpoint
                    if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                    {
                        // generate code_verifier
                        var codeVerifier = CryptoRandom.CreateUniqueId(32);

                        // store codeVerifier for later use
                        context.Properties.Items.Add("code_verifier", codeVerifier);

                        // create code_challenge
                        string codeChallenge;
                        using (var sha256 = SHA256.Create())
                        {
                            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                            codeChallenge = Base64Url.Encode(challengeBytes);
                        }

                        // add code_challenge and code_challenge_method to request
                        context.ProtocolMessage.Parameters.Add("code_challenge", codeChallenge);
                        context.ProtocolMessage.Parameters.Add("code_challenge_method", "S256");
                    }

                    return Task.CompletedTask;
                };

                options.Events.OnAuthorizationCodeReceived = context =>
                {
                    // only when authorization code is being swapped for tokens
                    if (context.TokenEndpointRequest?.GrantType == OpenIdConnectGrantTypes.AuthorizationCode)
                    {
                        // get stored code_verifier
                        if (context.Properties.Items.TryGetValue("code_verifier", out var codeVerifier))
                        {
                            // add code_verifier to token request
                            context.TokenEndpointRequest.Parameters.Add("code_verifier", codeVerifier);
                        }
                    }

                    return Task.CompletedTask;
                };
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    ValidateIssuer = true
                };
            })
            .AddJwtBearer(options =>
            {
                options.Authority = Configuration["Identity:Domain"];
                options.Audience = Configuration["Identity:Audience"];
            });

            services.AddAuthorization();
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }
            app.UseAuthentication();

            app.UseHttpsRedirection();
            app.UseMvc();
            // This line MUST be before "app.UseAuthorization();"
        }
    }
}