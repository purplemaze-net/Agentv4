using PPMV4.Agent.Logging;

class Agent
{
    static void Main()
    {
        Console.WriteLine("PurpleMaze Agent (V4)");
        Console.WriteLine("Copyright (©) 2022-" + DateTimeOffset.UtcNow.Date.Year.ToString());
        Console.WriteLine("MathiAs2Pique (@m2p_)");

#if WINDOWS
        new Log("Platform: Windows");
#elif LINUX
        new Log("Platform: Linux");
#endif
    }
}