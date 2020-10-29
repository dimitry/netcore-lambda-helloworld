using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using APIGatewayAuthorizerHandler;
using APIGatewayAuthorizerHandler.Error;
using APIGatewayAuthorizerHandler.Model;
using APIGatewayAuthorizerHandler.Model.Auth;
using Newtonsoft.Json;
using Microsoft.Extensions.DependencyInjection;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace API
{
    public class Handler
    {
        private ILambdaConfiguration Configuration { get; }

        public Handler()
        {
            var serviceCollection = new ServiceCollection();
            ConfigureServices(serviceCollection);
            var serviceProvider = serviceCollection.BuildServiceProvider();
            Configuration = serviceProvider.GetService<ILambdaConfiguration>();
        }
        
        public AuthPolicy Authorizer(TokenAuthorizerContext input, ILambdaContext context)
        {
            try
            {
                // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJnYXRld2F5SWQiOiJhMWZiNGRjOC0zY2Y2LTRlZTYtYmU1Zi03ZGI1ZjA3MDkxZDQiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.-WH60ifv_FTHbEkoU2TQgkHDpT9zgmQ1HzQDgqngGjA
                context.Logger.LogLine($"{nameof(input.AuthorizationToken)}: {input.AuthorizationToken}");
                // context.Logger.LogLine($"{nameof(input.MethodArn)}: {input.MethodArn}");

                // validate the incoming token
                // and produce the principal user identifier associated with the token
                string jwtSecret = "SECRET";
                string decodedJWT;
                try
                {
                    byte[] secretKey = Encoding.ASCII.GetBytes(jwtSecret);
                    decodedJWT = Jose.JWT.Decode(input.AuthorizationToken, secretKey);
                }
                catch (Exception ex)
                {
                    context.Logger.LogLine(ex.ToString());
                    throw new Exception("Bad token bro");
                }

                var pineappleJWT = System.Text.Json.JsonSerializer.Deserialize<PineappleJWTToken>(decodedJWT);

                // build apiOptions for the AuthPolicy
                var methodArn = ApiGatewayArn.Parse(input.MethodArn);
                var apiOptions = new ApiOptions(methodArn.Region, methodArn.RestApiId, methodArn.Stage);

                // this function must generate a policy that is associated with the recognized principal user identifier.
                // depending on your use case, you might store policies in a DB, or generate them on the fly

                // keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
                // and will apply to subsequent calls to any method/resource in the RestApi
                // made with the same token

                // the example policy below denies access to all resources in the RestApi
                var policyBuilder = new AuthPolicyBuilder(pineappleJWT.gatewayId, methodArn.AwsAccountId, apiOptions);
                // policyBuilder.DenyAllMethods();
                policyBuilder.AllowAllMethods();
                // policyBuilder.AllowMethod(HttpVerb.GET, "/users/username");

                // finally, build the policy
                var authResponse = policyBuilder.Build();

                // new! -- add additional key-value pairs
                // these are made available by APIGW like so: $context.authorizer.<key>
                // additional context is cached
                authResponse.Context.Add("key", "value"); // $context.authorizer.key -> value
                authResponse.Context.Add("number", 1);
                authResponse.Context.Add("bool", true);

                return authResponse;
            }
            catch (Exception ex)
            {
                if (ex is UnauthorizedException)
                    throw;

                // log the exception and return a 401
                context.Logger.LogLine(ex.ToString());
                throw new UnauthorizedException();
            }
        }

        public APIGatewayProxyResponse HelloWorld(APIGatewayProxyRequest request, ILambdaContext context)
        {
            // EXAMPLE: passing data from the authorizer
            if (request != null && request.RequestContext != null && request.RequestContext.Authorizer != null) {
                LogMessage(context, "----------------------");
                LogMessage(context, request.RequestContext.Authorizer["key"] as string);
                LogMessage(context, "----------------------");
            }

            // EXAMPLE: configuration
            string vaultVal = LambdaConfiguration.Configuration["VAULT"];
            context.Logger.LogLine($"VAULT: {vaultVal}");

            APIGatewayProxyResponse response;
            Dictionary<string, string> dict = new Dictionary<string, string>();
            dict.Add("hello", "world");
            response = CreateResponse(dict);
            return response;
        }

        public APIGatewayProxyResponse GetQuerystring(APIGatewayProxyRequest request, ILambdaContext context)
        {
            APIGatewayProxyResponse response;
            LogMessage(context, "Processing request started");
            if (request != null && request.QueryStringParameters.Count > 0)
            {
                try
                {
                    // var result = processor.CurrentTimeUTC();
                    response = CreateResponse(request.QueryStringParameters);
                    LogMessage(context, "First Parameter Value to read is: " + request.QueryStringParameters["foo"]);
                    LogMessage(context, "Processing request succeeded.");
                }
                catch (Exception ex)
                {
                    LogMessage(context, string.Format("Processing request failed - {0}", ex.Message));
                    response = CreateResponse(null);
                }
            }
            else
            {
                LogMessage(context, "Processing request failed - Please add queryStringParameter 'foo' to your request - see sample in readme");
                response = CreateResponse(null);
            }
            return response;
        }
        void LogMessage(ILambdaContext ctx, string msg)
        {
            ctx.Logger.LogLine(
                string.Format("{0}:{1} - {2}",
                    ctx.AwsRequestId,
                    ctx.FunctionName,
                    msg));
        }
        APIGatewayProxyResponse CreateResponse(IDictionary<string, string> result)
        {
            int statusCode = (result != null) ?
                (int)HttpStatusCode.OK :
                (int)HttpStatusCode.InternalServerError;

            string body = (result != null) ?
                JsonConvert.SerializeObject(result) : string.Empty;

            var response = new APIGatewayProxyResponse
            {
                StatusCode = statusCode,
                Body = body,
                Headers = new Dictionary<string, string>
                {
                    { "Content-Type", "application/json" },
                    { "Access-Control-Allow-Origin", "*" }
                }
            };

            return response;
        }

        private void ConfigureServices(IServiceCollection serviceCollection)
        {
            serviceCollection.AddTransient<ILambdaConfiguration, LambdaConfiguration>();
        }

    }



}
