using NUnitLite;
using System.Reflection;

namespace NUnitTests
{
    class Program
    {
        /// <summary>
        /// By Pressing F5, this will run all tests in the NUnitTests project. 
        /// The tests are categorized into AES and HMAC, and will be executed in 
        /// that order. After each category, the program will pause and wait for 
        /// the user to press any key before proceeding to the next category.
        /// </summary>
        /// <returns>the total of failed tests across all tests ran. (only seen when ran from a command prompt)</returns>
        static int Main(string[] args)
        {
            var GCM = false;
            var HMAC = false;

            if (args.Length == 1)
            {
                foreach (var arg in args.Select(s => s.ToLower()))
                {
                    if (arg.Equals("--gcm"))
                    {
                        GCM = true;
                        break;
                    }
                    else if (arg.Equals("--hmac"))
                    {
                        HMAC = true;
                        break;
                    }
                    else if (arg.Equals("--all"))
                    {
                        HMAC = true;
                        GCM = true;
                        break;
                    }
                    else if (arg.Equals("--help") || arg.Equals("-?"))
                    {
                        ShowHelp();
                        return 0;
                    }
                }
            }
            else
            {
                GCM = true;
                HMAC = true;
            }

            Console.CursorVisible = false;
            var assembly = typeof(Program).GetTypeInfo().Assembly;
            int totalFailedTests = 0;

            // if both tests, then running all, will show all results in TestResult.xml
            // if separated, TestResult.xml will be overwritten by the last run.
            if (GCM && HMAC)
            {
                // Run AES and HMAC tests 
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("=== Starting AES-GCM and AES-GCM Tests ===");
                Console.ResetColor();

                totalFailedTests += new AutoRun(assembly).Execute(new[] { "--where", "cat == GCM || cat == HMAC" });

                // Pause to show results
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n>>> AES GCM and HMAC Categories Complete. Press any key to close execution...");
                Console.ResetColor();
                Console.ReadKey(true);
            }            
            else if (GCM)
            {
                // Run AES tests first
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("=== Starting AES-GCM Tests ===");
                Console.ResetColor();

                totalFailedTests += new AutoRun(assembly).Execute(new[] { "--where", "cat == GCM" });

                // Pause to show results
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n>>> AES-GCM Category Complete. Press any key to close execution...");
                Console.ResetColor();
                Console.ReadKey(true);
            }            
            else if (HMAC)
            {
                // Run HMAC tests next
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("=== Starting AES /w HMAC Tests ===");
                Console.ResetColor();

                totalFailedTests += new AutoRun(assembly).Execute(new[] { "--where", "cat == HMAC" });

                // Pause to show results
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n>>> AES HMAC Category Complete. Press any key to close execution...");
                Console.ResetColor();
                Console.ReadKey(true);
            }

            Console.CursorVisible = true;
            return totalFailedTests;
        }

        static void ShowHelp()
        {
            Console.WriteLine();
            Console.WriteLine("--all\tRuns all NUnit tests.  This is default, when not passing any arguments.");
            Console.WriteLine("--gcm\tRuns only aes-gcm NUnit tests.");
            Console.WriteLine("--hmac\tRuns only aes w/ hmac NUnit tests.");
            Console.WriteLine();
            Console.WriteLine("--help, -?\tShows this argument screen.");
            Console.WriteLine();
        }
    }
}
