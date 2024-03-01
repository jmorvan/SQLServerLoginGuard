using NetFwTypeLib;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;

namespace SQLServerLoginGuard
{
    internal class Program
    {
        const int delay = 10000;
        const int eventLinesToRequest = 10000;
        const int blacklistTreshold = 5;

        static void Main(string[] args)
        {

            var helper = new SQLServerLoginGuardHelper(delay, eventLinesToRequest, blacklistTreshold);

            if (args.Length > 1 && args[0]=="test-ip"){
                var ip = helper.getIp(args[1]);

                Console.WriteLine(ip);
            }
            else if (args.Length > 0 && args[0] == "get-log")
            {
                var logs = helper.getLogEntries();

                foreach (var logEntry in logs) { Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(new { logEntry.EventID,logEntry.Message,logEntry.TimeGenerated })); }
            }
            else
            {
                helper.serviceWorker();
            }

            Console.ReadLine();
        }
    }
}
