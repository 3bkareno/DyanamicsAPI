# Use the ASP.NET Core 8.0 runtime as base image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app

# Copy HTTPS dev certificate inside container
COPY certs/devcert.pfx /https/devcert.pfx

# Set environment variables for Kestrel to find the certificate
ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/https/devcert.pfx
ENV ASPNETCORE_Kestrel__Certificates__Default__Password=P@ssw0rd

# Use the SDK image to build the app
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy the project file and restore dependencies
COPY ["DyanamicsAPI.csproj", "./"]
RUN dotnet restore "DyanamicsAPI.csproj"

# Copy the entire source code and publish the app
COPY . .
RUN dotnet publish "DyanamicsAPI.csproj" -c Release -o /app/publish

# Final image that runs the app
FROM base AS final
WORKDIR /app

# Copy published output from build stage
COPY --from=build /app/publish .

# Expose ports matching your launchSettings
EXPOSE 8080
EXPOSE 8081

# Run the app DLL
ENTRYPOINT ["dotnet", "DyanamicsAPI.dll"]
