Метрики ПР4 рассчитаны анализатором MetricsRunner по исходникам проекта.


dotnet restore metrics/MetricsRunner/MetricsRunner.csproj --configfile metrics/NuGet.Config
dotnet run --no-restore --project metrics/MetricsRunner/MetricsRunner.csproj -- src/GuestPass.Api metrics/metrics-recalculated.json comparison/BeforeRefactoring.cs.txt src/GuestPass.Api/PassesController.cs src/GuestPass.Api/PassService.cs

