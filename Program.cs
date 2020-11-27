using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using DnsClient;
using DnsClient.Protocol;

namespace GetDnsRecords
{
    class Program
    {
        private static LookupClient client = null;
        private static NameServer nameServer = new NameServer(NameServer.GooglePublicDns);
        private static NameServer nameServer2 = new NameServer(IPAddress.Parse("103.245.91.248"));
        
        static void Main(string[] args)
        {
            IEnumerable<string> readLines = File.ReadLines(args[0]);

            File.AppendAllText($"output.csv", 
                "domain,domain-ttl,ns,ns-ttl,soa,soa-ttl,mx,mx-priority,mx-ttl,txt,txt-ttl,dkim,dkim-ttl,dmarc,dmarc-ttl\n");
            
            foreach (string host in readLines)
            {
                Console.WriteLine("Processing " + host);
                // string resolver = "103.245.91.248";
                // string resolver = "8.8.8.8";
                // string soa = DigThis("A", host, resolver);
                // string mxs = DigThis("MX", host, resolver);
                // string nss = DigThis("NS", host, resolver);
                // string txts = DigThis("TXT", host, resolver);
                
                
                client = new LookupClient(nameServer);
                client.UseCache = false;
                IDnsQueryResponse nsResponse = client.Query(host, QueryType.NS);

                string result = "";
                try
                {
                    IDnsQueryResponse nsAResponse =
                        client.Query((nsResponse.Answers[0] as NsRecord)?.NSDName, QueryType.A);
                    NameServer ns = new NameServer((nsAResponse.Answers[0] as ARecord)?.Address);
                    
                    client = new LookupClient(ns);
                    client.UseCache = false;
                    IDnsQueryResponse aResponse = client.Query(host, QueryType.A);
                    IDnsQueryResponse mxResponse = client.Query(host, QueryType.MX);
                    IDnsQueryResponse soaResponse = client.Query(host, QueryType.SOA);
                    IDnsQueryResponse txtResponse = client.Query(host, QueryType.TXT);
                    
                    // 
                    IDnsQueryResponse ucResponse = client.Query("uckey._domainkey." + host, QueryType.TXT);
                    IDnsQueryResponse dmResponse = client.Query("_dmarc." + host, QueryType.TXT);

                    //
                    string doa = ParseRecord(aResponse, isA: true);
                    string soa = ParseRecord(soaResponse);
                    string mxs = ParseRecord(mxResponse, isMx: true);
                    string nss = ParseRecord(nsResponse);
                    string txts = ParseRecord(txtResponse);
                    string ucs = ParseRecord(ucResponse);
                    string dmr = ParseRecord(dmResponse);

                    // string result = $"{host} | {soa}NS\n{nss}MX\n{mxs}TXT\n{txts}\n";
                    result = $"{host},{doa},{nss},{soa},{mxs},{txts},{ucs},{dmr}\n";
                }
                catch (Exception e)
                {
                    result = $"{host},No record,No record,No record,No record,No record,No record,No record,No record,No record,No record,No record,No record\n";
                }
                
                File.AppendAllText($"output.csv", result);
            }
        }

        public class Record
        {
            public Record(string host, string type, string value, string ttl)
            {
                Host = host;
                Type = type;
                Value = value;
                Ttl = ttl;
            }

            public string Host { get; set; }
            public string Type { get; set; }
            public string Ttl { get; set; }
            public string Value { get; set; }
        }
        
        private static string DigThis(string record, string host, string dns, bool trace = false)
        {
            string t = trace ? "+trace" : "";
            string strCmdText = $"{record} {host.Trim()} +noauthority +noquestion +noadditional +nostats {t} @{dns}";

            // Start the child process.
            Process p = new Process();
            // Redirect the output stream of the child process.
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = @"C:\Users\Ijat\Documents\Softwares\Bind\dig.exe";
            p.StartInfo.Arguments = strCmdText;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            string pattern = @"([1-9A-Za-z.]*)\s+(\d+)\s+\w+\s+(\w+)\s+(.*)";
            Match match = Regex.Match(output, pattern, RegexOptions.IgnoreCase);
            int matchCount = 0;
            string all = "";
            Dictionary<string, Record> records = new Dictionary<string, Record>();
            while (match.Success)
            {
                string ttl = "";
                string result = "";
                string type = "";
                string thost = "";
                
                for (int i = 1; i <= 4; i++)
                {
                    Group g = match.Groups[i];
                    if (i == 2)
                        ttl = g.Value.Trim();
                    else if (i == 4)
                        result = g.Value.Trim(); 
                    else if (i == 3) 
                        type = g.Value.Trim(); 
                    else if (i == 1)
                        thost = g.Value.Trim();
                }

                if (ttl != "" && result != "" && type != "" && thost != "" && type == record && thost == $"{host}.")
                {
                    if (records.ContainsKey(result))
                        records.Remove(result);
                    records.Add(result, new Record(thost, type, result, ttl));
                }

                match = match.NextMatch();
            }

            foreach (Record r in records.Values)
            {
                all += $"{r.Value} | TTL {r.Ttl}\n";
            }
            
            return string.IsNullOrEmpty(all) ? "No record\n" : all;
        }

        static string ParseRecord(IDnsQueryResponse dnsQueryResponse, bool isA = false, bool isMx = false)
        {
            string output = "";
            string value = "";
            string ttl = "";
            string mxp = "";
            foreach (DnsResourceRecord record in dnsQueryResponse.Answers)
            {
                switch (record.RecordType)
                {
                    case ResourceRecordType.MX:
                    {
                        MxRecord mxRecord = record as MxRecord;
                        if (mxRecord != null)
                        {
                            value += mxRecord.Exchange + "\n";
                            ttl += mxRecord.InitialTimeToLive + "\n";
                            mxp += mxRecord.Preference + "\n";
                            // output += $"{mxRecord.Exchange} | TTL {mxRecord.InitialTimeToLive}\n";
                        }
                        break;
                    }
                    case ResourceRecordType.SOA:
                    {
                        SoaRecord soaRecord = record as SoaRecord;
                        if (soaRecord != null)
                        {
                            value += soaRecord.ToString() + "\n";
                            ttl += soaRecord.Minimum + "\n";
                            // output += $"SOA TTL {soaRecord.Minimum}\n";
                        }
                        break;
                    }
                    case ResourceRecordType.NS:
                    {
                        NsRecord nsRecord = record as NsRecord;
                        if (nsRecord != null)
                        {
                            value += nsRecord.NSDName + "\n";
                            ttl += nsRecord.InitialTimeToLive + "\n";
                            // output += $"{nsRecord.NSDName} | TTL {nsRecord.InitialTimeToLive}\n";
                        }
                        break;
                    }
                    case ResourceRecordType.A:
                    {
                        ARecord nsRecord = record as ARecord;
                        if (nsRecord != null)
                        {
                            return $"{nsRecord.InitialTimeToLive}";
                        }
                        return "No record";
                    }
                    case ResourceRecordType.TXT:
                    {
                        TxtRecord txtRecord = record as TxtRecord;
                        if (txtRecord != null)
                        {
                            foreach (string txt in txtRecord.Text)
                            {
                                value += "\"\"" + txt + "\"\"\n";
                                ttl += txtRecord.InitialTimeToLive + "\n";
                                // output += $"\"{txt}\" | TTL {txtRecord.InitialTimeToLive}\n";   
                            }
                        }
                        break;
                    }
                }
            }

            if (!string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(ttl))
            {
                if (string.IsNullOrEmpty(mxp))
                    output = $"\"{value.Trim()}\",\"{ttl.Trim()}\"";
                else
                {
                    output = $"\"{value.Trim()}\",\"{mxp.Trim()}\",\"{ttl.Trim()}\"";
                }
            }
            else
            {
                if (isA)
                    output = "No record";
                else if (isMx)
                    output = "No record,No record,No record";
                else
                    output = "No record,No record";
            }
            
            if (string.IsNullOrEmpty(output)) return "No record\n";
            return output;
        }

        public static string GetTTL(string host)
        {
            IDnsQueryResponse dnsQueryResponse = client.Query(host, QueryType.ANY);
            return "";
        }
    }
}