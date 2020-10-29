using Microsoft.Extensions.Configuration;

namespace API
{
    public interface ILambdaConfiguration
    {
        IConfigurationRoot Configuration { get; }
    }
}