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
            var AES = false;
            var HMAC = false;

            if (args.Length == 1)
            {
                foreach (var arg in args.Select(s => s.ToLower()))
                {
                    if (arg.Equals("--aes"))
                    {
                        AES = true;
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
                        AES = true;
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
                AES = true;
                HMAC = true;
            }

            Console.CursorVisible = false;
            var assembly = typeof(Program).GetTypeInfo().Assembly;
            int totalFailedTests = 0;

            if (AES)
            {
                // 1. Run AES tests first
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("=== Starting AES Tests ===");
                Console.ResetColor();

                totalFailedTests += new AutoRun(assembly).Execute(new[] { "--where", "cat == AES" });

                // Pause between categories
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n>>> AES Category Complete. Press any key to {(HMAC ? "coninue to HMAC" : "close execution")}...");
                Console.ResetColor();
                Console.ReadKey(true);
            }

            if (HMAC)
            {
                // 2. Run HMAC tests next
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("=== Starting HMAC Tests ===");
                Console.ResetColor();

                totalFailedTests += new AutoRun(assembly).Execute(new[] { "--where", "cat == HMAC" });

                // Final wrap up
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\nAll test categories completed. Press any key to close execution...");
                Console.ResetColor();
                Console.ReadKey(true);
            }

            Console.CursorVisible = true;
            return totalFailedTests;
        }

        static void ShowHelp()
        {
            //"--all"
            //"--aes"
            //"--hmac"
            //"--help"
            //"-h"
            //"-?"
        }
    }
}
