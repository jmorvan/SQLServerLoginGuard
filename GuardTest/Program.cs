using NetFwTypeLib;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace GuardTest
{
    internal class Program
    {
        static void Main(string[] args)
        {

            EventLog log = new EventLog("Application");
            var entries = log.Entries.Cast<EventLogEntry>()
                         .Where(x => x.InstanceId == 3221243928)
                         .Select(x => new
                         {
                             x.MachineName,
                             x.Site,
                             x.Source,
                             x.Message,
                             x.TimeGenerated,
                             Ip = getIp(x.Message)
                         }).Take(100).OrderByDescending(x => x.TimeGenerated).ToList();
            var dic = new Dictionary<string, int>();



            entries.ForEach(x =>
            {
                if (dic.ContainsKey(x.Ip)) dic[x.Ip]++;
                else dic[x.Ip] = 1;
            });

            Console.WriteLine("SUSPICIOUS IPs :");
            if (dic.Count > 0) Console.WriteLine("nothing to declare");
            foreach (var entry in dic)
            {
                Console.WriteLine(entry);
            }

            dic.Where(x => x.Value > 10).ToList().ForEach(x => setFwRule(x.Key));



            Console.ReadLine();
        }

        static void setFwRule(string ip)
        {

            var name = $"SQL Suspicious {ip}";
            Console.WriteLine("");
            Console.WriteLine($"Setting firewall rule named: {name}");

            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            dynamic fwPolicy2 = Activator.CreateInstance(tNetFwPolicy2) as dynamic;
            IEnumerable Rules = fwPolicy2.Rules as IEnumerable;
            
            var rNames = new List<string>();

            foreach (dynamic rule in Rules)
            {
                rNames.Add(rule.Name);
            }

            if (rNames.Any(x => x == name))
            {
                Console.WriteLine("rule exists => abort");
            }
            else
            {
                Console.WriteLine("rule does not exists => create");
                var currentProfiles = fwPolicy2.CurrentProfileTypes;

                // Let's create a new rule
                INetFwRule2 firewallRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                firewallRule.Name = name;
                firewallRule.Description = "Block Incoming Connections from IP Address.";
                firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                firewallRule.Enabled = true;
                firewallRule.InterfaceTypes = "All";
                firewallRule.RemoteAddresses = ip;

                INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                firewallPolicy.Rules.Add(firewallRule);
                Console.WriteLine("Ok!");
            }

        }

        static string getIp(string msg)
        {
            string pattern = @"(?:[0-9]{1,3}\.){3}[0-9]{1,3}";
            RegexOptions options = RegexOptions.Multiline;
            var res = Regex.Matches(msg, pattern, options);

            if (res.Count < 1 )
            {
                return null;
            }

            return res[0].Value;
        }
    }
}
