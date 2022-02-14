module GiraffeWithIdentity.App

open System
open System.IO
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Cors.Infrastructure
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Http
open Microsoft.AspNetCore.WebUtilities
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Microsoft.Extensions.DependencyInjection
open System.Threading.Tasks

open System.Security.Claims // for 'Claim' class

open Giraffe
open Giraffe.Antiforgery

open Microsoft.AspNetCore.Identity
open Microsoft.EntityFrameworkCore
open Microsoft.EntityFrameworkCore.Sqlite
// ---------------------------------
// Views
// ---------------------------------

open Microsoft.AspNetCore.Antiforgery

module Views =
    open Giraffe.ViewEngine

    let layout (content: XmlNode list) =
        html [] [
            head [] [
                title []  [ encodedText "GiraffeWithIdentity" ]
                link [ _rel  "stylesheet"
                       _type "text/css"
                       _href "/main.css" ]
            ]
            body [] content
        ]

    let registerPage (errors : string list) (token : AntiforgeryTokenSet) = 
        [
            h1 [] [str "Please Register"]
            form [_method "post"] [
                input [_type "text"; _placeholder "email"; _name "email"] 
                input [_type "password"; _placeholder "password"; _name "password"] 
                input [_type "submit"; _value "register"] 
                antiforgeryInput token
            ]
            a [_href "/Account/Login"] [str "Already registered?"]
            ul [] (errors |> List.map (fun err -> li [] [str err]))
        ] |> layout

    let thanksForRegisteringPage = 
        [
            p [] [ str "thanks for registering, we'll send you a confirmation email soon!" ]
            a [_href "/Account/Login"] [str "go back to login page"]
        ] |> layout

    let emailVerificationPage (success : bool) = 
        [
            if success then
                yield p [] [ str "Thanks for verifying your email address! You can now login." ]
            else
                yield p [] [ str "Oops, something is wrong with your verification link, please retry" ]
            yield a [_href "/Account/Login"] [str "go back to login page"]
        ] |> layout

    let loginPage (justFailed : bool) (token : AntiforgeryTokenSet) = 
        [
            yield h1 [] [str "Please Login"]
            yield form [_method "post"] [
                input [_type "text"; _placeholder "email"; _name "email"] 
                input [_type "password"; _placeholder "password"; _name "password"] 
                input [_type "submit"; _value "login"] 
                antiforgeryInput token
            ]
            if justFailed then 
                yield p [ _style "color: Red;" ] [ str "Login failed." ]
            yield a [_href "/Account/Register"] [str "Register"]
        ] |> layout

    let userPage (user : IdentityUser) (token : AntiforgeryTokenSet) =
        [
            p [] [
                sprintf "User name: %s, Email: %s" user.UserName user.Email
                |> str
            ]
            form [_method "post"; _action "/Account/Logout"] [
                input [_type "submit"; _value "Logout"] 
                antiforgeryInput token
            ]
        ] |> layout

// ---------------------------------
// Web app
// ---------------------------------

[<CLIMutable>]
type RegisterModel = 
    {
        // it's okay this is capitalized. 
        Email : string
        Password : string
    }

[<CLIMutable>]
type LoginModel = 
    {
        Email : string
        Password : string
    }

[<CLIMutable>]
type EmailVerificationModel = 
    {
        UserId: string
        Token : string
    }

let registerHandler : HttpHandler =
    fun next ctx -> 
        task {
            let userManager = ctx.GetService<UserManager<IdentityUser>>()
            let! form = ctx.TryBindFormAsync<RegisterModel>()
            match form with
            | Error _ -> 
                return! csrfHtmlView (Views.registerPage ["Something went wrong, please try again"]) next ctx
            | Ok form -> 
                let user = IdentityUser(Email = form.Email, UserName = form.Email)

                let! result = userManager.CreateAsync(user, form.Password)

                // let! f = next ctx
                if result.Succeeded then
                    printfn "REGISTER SUCCEEDED" 

                    let! res1 = userManager.AddToRoleAsync(user, "USER")
                    // let! result1 = userManager.AddToRoleAsync(user, "user")
                    // result1 |> Async.Ignore

                    let! res2 = userManager.AddClaimsAsync(user, [ 
                        Claim("tier", "free") // switch to 'paid' when user subscribes.
                    ])

                    let! token = userManager.GenerateEmailConfirmationTokenAsync(user)
                    let baseUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}/Account/Verify"
                    let url = QueryHelpers.AddQueryString(baseUrl, dict["UserId", user.Id ; "Token", token])

                    // !!! 
                    // This is where you would send an email to the user, with somewthing like System.Net.Mail or similar
                    // However, for this sample we're just going to print it to the console.
                    // !!!
                    printfn "***********\nYour verification url is: %s\n***********" url

                    return! redirectTo false "/Account/RegisterThanks" next ctx
                else
                    printfn "REGISTER FAILED" 
                    // result.Errors contains stuff like:
                    //  Passwords must have at least one non alphanumeric character.
                    //  Passwords must have at least one digit ('0'-'9').
                    //  Passwords must have at least one uppercase ('A'-'Z').
                    let errors = result.Errors |> Seq.map (fun e -> e.Description)  |> List.ofSeq
                    return! csrfHtmlView (Views.registerPage errors) next ctx
        }

let loginHandler : HttpHandler =
    fun next ctx -> 
        task {
            let! model = ctx.TryBindFormAsync<LoginModel>()
            match model with
            | Ok model -> 
                let signInManager = ctx.GetService<SignInManager<IdentityUser>>()
                let! result = signInManager.PasswordSignInAsync(model.Email, model.Password, true, false)
                match result.Succeeded with
                | true  -> return! redirectTo false "/User" next ctx
                | false -> return! csrfHtmlView (Views.loginPage true) next ctx
            | Error _ -> return! csrfHtmlView (Views.loginPage true) next ctx
        }

let logoutHandler : HttpHandler =
    fun next ctx -> 
        task {
            let signInManager = ctx.GetService<SignInManager<IdentityUser>>()
            do! signInManager.SignOutAsync()
            return! redirectTo false "/Account/Login" next ctx
        }

let userPageHandler : HttpHandler = 
    fun next ctx -> 
        task {
            let userManager = ctx.GetService<UserManager<IdentityUser>>()
            let! user = userManager.GetUserAsync ctx.User
            return! (user |> Views.userPage |> csrfHtmlView) next ctx
        }

let emailVerificationHandler : HttpHandler = 
    fun next ctx -> 
        task {
            let userManager = ctx.GetService<UserManager<IdentityUser>>()
            match ctx.TryBindQueryString<EmailVerificationModel>() with
            | Ok qs -> 
                let! user = userManager.FindByIdAsync(qs.UserId)

                if not (isNull user) then
                    let! result = userManager.ConfirmEmailAsync(user, qs.Token);                
                    return! (Views.emailVerificationPage result.Succeeded |> htmlView) next ctx
                else
                    return! (Views.emailVerificationPage false |> htmlView) next ctx
            | Error s -> 
                return! (Views.emailVerificationPage false |> htmlView) next ctx
        }

let mustBeLoggedIn : HttpHandler =
    requiresAuthentication (redirectTo false "/Account/Login")

let webApp =
    choose [
        GET >=> 
            choose [
                route "/Account/Register"       >=> csrfHtmlView (Views.registerPage [])
                route "/Account/Login"          >=> csrfHtmlView (Views.loginPage false)
                route "/Account/RegisterThanks" >=> htmlView Views.thanksForRegisteringPage
                route "/Account/Verify"         >=> emailVerificationHandler

                mustBeLoggedIn >=> route "/User" >=> userPageHandler
            ]
        POST >=> requiresCsrfToken (setStatusCode 403 >=> text "Forbidden") >=> 
            choose [
                route "/Account/Register" >=> registerHandler
                route "/Account/Login" >=> loginHandler
                route "/Account/Logout" >=> logoutHandler
            ]
        setStatusCode 404 >=> text "Not Found" ]

// ---------------------------------
// Error handler
// ---------------------------------

let errorHandler (ex : Exception) (logger : ILogger) =
    logger.LogError(ex, "An unhandled exception has occurred while executing the request.")
    clearResponse >=> setStatusCode 500 >=> text ex.Message

// ---------------------------------
// Config and Main
// ---------------------------------

let configureCors (builder : CorsPolicyBuilder) =
    builder
        .WithOrigins(
            "http://localhost:5000",
            "https://localhost:5001")
       .AllowAnyMethod()
       .AllowAnyHeader()
       |> ignore

let configureApp (app : IApplicationBuilder) =
    let env = app.ApplicationServices.GetService<IWebHostEnvironment>()
    (match env.IsDevelopment() with
    | true  ->
        app.UseDeveloperExceptionPage()
    | false ->
        app .UseGiraffeErrorHandler(errorHandler)
            .UseHttpsRedirection())
        .UseCors(configureCors)
        .UseStaticFiles()
        .UseAuthentication()
        // .UseAuthorization()
        .UseGiraffe(webApp)

let configureServices (services : IServiceCollection) =
    services.AddCors()    |> ignore
    services.AddGiraffe() |> ignore
    services.AddDbContext<MyDbContext.ApplicationDbContext>(fun options ->  
            options.UseSqlite("Filename=identity.db") |> ignore
            ) |> ignore

    // IdentityUser, IdentityRole from MS.ASP.Identity
    services.AddIdentity<IdentityUser, IdentityRole>(fun options -> 
            options.Password.RequireLowercase <- true
            options.Password.RequireUppercase <- true
            options.Password.RequireDigit <- true
            options.Lockout.MaxFailedAccessAttempts <- 5
            options.Lockout.DefaultLockoutTimeSpan <- TimeSpan.FromMinutes(15)
            options.User.RequireUniqueEmail <- true
            // options.SignIn.RequireConfirmedEmail <- true;
            )
        // tell asp.net identity to use the above store
        .AddEntityFrameworkStores<MyDbContext.ApplicationDbContext>()
        .AddDefaultTokenProviders() // need for email verification token generation
        |> ignore

    services.AddAntiforgery() |> ignore

    services.ConfigureApplicationCookie(fun options -> 
        options.LoginPath <- "/Account/Login"
        options.AccessDeniedPath <- "/Account/AccessDenied")
    |> ignore

let configureLogging (builder : ILoggingBuilder) =
    builder.AddConsole()
           .AddDebug() |> ignore

[<EntryPoint>]
let main args =
    let contentRoot = Directory.GetCurrentDirectory()
    let webRoot     = Path.Combine(contentRoot, "WebRoot")
    Host.CreateDefaultBuilder(args)
        .ConfigureWebHostDefaults(
            fun webHostBuilder ->
                webHostBuilder
                    .UseContentRoot(contentRoot)
                    .UseWebRoot(webRoot)
                    .Configure(Action<IApplicationBuilder> configureApp)
                    .ConfigureServices(configureServices)
                    .ConfigureLogging(configureLogging)
                    |> ignore)
        .Build()
        .Run()
    0
