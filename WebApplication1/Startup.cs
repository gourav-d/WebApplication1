using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace WebApplication1
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

			services.AddAuthentication(o =>
			{
				o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			})
				.AddJwtBearer(options => {
				options.RequireHttpsMetadata = false;
				options.SaveToken = true;
				options.TokenValidationParameters = new TokenValidationParameters()
				{
					ValidateIssuer = true,
					ValidateAudience = true,
					ValidateIssuerSigningKey = true,
					ValidIssuer = "http://mysite.com", //some string, normally web url,  
					ValidAudience = "http://mysite.com",
					IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my_secret_key_12345"))
				};

				options.Events = new JwtBearerEvents
				{
					OnMessageReceived = context =>
					{
						context.Token = context.Request.Cookies["X-Access-Token"];
						return Task.CompletedTask;
					},
				};
			}).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, o =>
			{
				o.ExpireTimeSpan = TimeSpan.FromMinutes(30); // optional
			});
			//services.UseJwtBearerAuthentication(
			//	new JwtBearerAuthenticationOptions
			//	{
			//		AuthenticationMode = AuthenticationMode.Active,
			//		TokenValidationParameters = new TokenValidationParameters()
			//		{
			//			ValidateIssuer = true,
			//			ValidateAudience = true,
			//			ValidateIssuerSigningKey = true,
			//			ValidIssuer x= "http://mysite.com", //some string, normally web url,  
			//			ValidAudience = "http://mysite.com",
			//			IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my_secret_key_12345"))
			//		}
			//	});


			var multiSchemePolicy = new AuthorizationPolicyBuilder(
				CookieAuthenticationDefaults.AuthenticationScheme,
				JwtBearerDefaults.AuthenticationScheme)
			  .RequireAuthenticatedUser()
			  .Build();

			services.AddAuthorization(o => o.DefaultPolicy = multiSchemePolicy);


			services.AddRazorPages();
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}
			else
			{
				app.UseExceptionHandler("/Error");
				// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
				app.UseHsts();
			}

			app.UseHttpsRedirection();
			app.UseStaticFiles();

			app.UseRouting();

			app.UseAuthentication();

			//app.UseMvc(routes =>
			//{
			//	routes.MapRoute(
			//		name: "default",
			//		template: "{controller=Home}/{action=Index}/{id?}");
			//});

			app.UseAuthorization();

			//app.UseMvcWithDefaultRoute();

			app.UseEndpoints(endpoints =>
			{
				endpoints.MapControllerRoute(
					name: "default",
					pattern: "{controller=Home}/{action=Index}/{id?}");
			});

			//app.UseEndpoints(endpoints =>
			//{
			//	endpoints.MapRazorPages();
			//});


		}
	}
}
