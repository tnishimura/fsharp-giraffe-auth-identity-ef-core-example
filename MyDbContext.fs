
module MyDbContext
open Microsoft.AspNetCore.Identity
open Microsoft.AspNetCore.Identity.EntityFrameworkCore
open Microsoft.EntityFrameworkCore
open Microsoft.EntityFrameworkCore.Sqlite
open Microsoft.EntityFrameworkCore.Design // for IDesignTimeDbContextFactory

type ApplicationDbContext(options : DbContextOptions<ApplicationDbContext>) = 
    inherit IdentityDbContext(options)

    // OPTIONAL - you can seed your identity database with initial data.
    // below, we're creating some roles we'll use later.
    // See https://docs.microsoft.com/en-us/ef/core/modeling/data-seeding
    override __.OnModelCreating (modelBuilder : ModelBuilder) =
        base.OnModelCreating(modelBuilder)

        modelBuilder.Entity<IdentityRole>().HasData(
            [|
                // https://stackoverflow.com/a/39521545/ - NormalizedName needs to be set manually
                IdentityRole(Name = "admin", NormalizedName = "ADMIN")
                IdentityRole(Name = "user", NormalizedName = "USER")
            |]) |> ignore

// EFCore requires a "design time" instance of ApplicationDbContext
// 
// in a C# ASP.NET Core application, EFCore would look in the Program class for CreateHostBuilder method.
// in F#/Giraffe, we don't have a Program (someone correct me if I'm wrong)
// so, as an alternative way of telling efcore how to build a context, we create a factory.
// https://docs.microsoft.com/en-us/ef/core/cli/dbcontext-creation?tabs=dotnet-core-cli
// results in a little code duplication but not much
type ApplicationDbContextFactory() =
    interface IDesignTimeDbContextFactory<ApplicationDbContext> with
        member __.CreateDbContext (args: string[]) =
            let optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>()
            optionsBuilder.UseSqlite("Data Source=identity.db") |> ignore
            new ApplicationDbContext(optionsBuilder.Options)

// in c#:
// using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
// using Microsoft.EntityFrameworkCore;
// 
// namespace WebAppContext {
//     public class ApplicationDbContext : IdentityDbContext {
//         public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) {
//         }
//     }
// }


