namespace PPMV4.Agent.Logging;

public enum LogLevel {
    Info,
    Warning,
    Error
}

public class LogHandler : IDisposable {
    private static LogHandler? Instance = null;
    private readonly StreamWriter Writer;
    private object Lock;

    private LogHandler() {
        Lock = new();
        Writer = new StreamWriter("ppm-agent.log", true);
        Write("=================== PurpleMaze-Agent is starting ===================");
    }

    public static LogHandler GetInstance() {
        if(Instance is null)
            Instance = new();
        return Instance;
    }

    public void Dispose() {
        Writer?.Dispose();
    }

    public void Write(string message){
        lock(Lock){
            Writer.WriteLine(message);
            Writer.Flush();
        }
    }
}

public class Log
{
    public Log(string message, LogLevel level = LogLevel.Info) {
        LogHandler handler = LogHandler.GetInstance();
        
        // Write in file
        var formattedMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {GetPrefix(level)} {message}";
        handler.Write(formattedMessage);
        
        ConsoleColor originalColor = Console.ForegroundColor;
        Console.ForegroundColor = GetColor(level);
        Console.WriteLine(formattedMessage);
        Console.ForegroundColor = originalColor;
    }

    private static string GetPrefix(LogLevel level) {
        return level switch{
            LogLevel.Info => "[/]",
            LogLevel.Warning => "[.]",
            LogLevel.Error => "[!]",
            _ => "[ ]"
        };
    }

    private static ConsoleColor GetColor(LogLevel level) {
        return level switch{
            LogLevel.Info => ConsoleColor.Cyan,
            LogLevel.Warning => ConsoleColor.Yellow,
            LogLevel.Error => ConsoleColor.Red,
            _ => ConsoleColor.White
        };
    }
}
