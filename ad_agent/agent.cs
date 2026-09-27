using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ADWatchdogAgent
{
    class Program
    {
        // ====================================================================
        // CONFIGURATION
        // ====================================================================
        static string Identity = "alpha";
        static string TwinIdentity = "bravo";
        static string ServerHost = "127.0.0.1";
        static int ServerPort = 8000;
        static string Endpoint = "/api/ad_triage";
        static int IntervalSec = 300; // 5 minutes (300 seconds)
        static bool DebugMode = false;

        // ====================================================================
        // WIN32 NATIVE NETAPI32 P/INVOKE DEFINITIONS
        // ====================================================================
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USER_INFO_0
        {
            public string usri0_name;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct GROUP_USERS_INFO_0
        {
            public string grui0_name;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_0
        {
            public IntPtr lgrmi0_sid;
            public int lgrmi0_sidusage;
            public string lgrmi0_name;
        }

        [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int NetUserEnum(
            string servername,
            int level,
            int filter,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int NetGroupGetUsers(
            string servername,
            string groupname,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("Netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int NetLocalGroupGetMembers(
            string servername,
            string groupname,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("kernel32.dll")]
        public static extern bool AllocConsole();

        [DllImport("kernel32.dll")]
        public static extern bool AttachConsole(int dwProcessId);

        // ====================================================================
        // 1. ACTIVE DIRECTORY & LOCAL USER AUDITING
        // ====================================================================
        static List<string> QueryActiveDirectoryUsers()
        {
            List<string> users = new List<string>();
            IntPtr bufPtr = IntPtr.Zero;
            int resumeHandle = 0;
            int entriesRead, totalEntries;

            try
            {
                int status = NetUserEnum(null, 0, 2 /* FILTER_NORMAL_ACCOUNT */, out bufPtr, -1, out entriesRead, out totalEntries, ref resumeHandle);
                if ((status == 0 || status == 234) && bufPtr != IntPtr.Zero)
                {
                    IntPtr currentPtr = bufPtr;
                    for (int i = 0; i < entriesRead; i++)
                    {
                        USER_INFO_0 user = (USER_INFO_0)Marshal.PtrToStructure(currentPtr, typeof(USER_INFO_0));
                        if (!string.IsNullOrEmpty(user.usri0_name))
                        {
                            users.Add(user.usri0_name);
                        }
                        currentPtr = (IntPtr)((long)currentPtr + Marshal.SizeOf(typeof(USER_INFO_0)));
                    }
                }
            }
            catch { }
            finally
            {
                if (bufPtr != IntPtr.Zero) NetApiBufferFree(bufPtr);
            }

            // Fallback for isolated standalone environments
            if (users.Count == 0)
            {
                users.Add("Administrator");
                users.Add("Guest");
            }

            return users;
        }

        static List<string> QueryDomainAdmins()
        {
            List<string> admins = new List<string>();
            IntPtr bufPtr = IntPtr.Zero;
            int resumeHandle = 0;
            int entriesRead, totalEntries;

            // 1. First try Domain Admins (on Domain Controller)
            try
            {
                int status = NetGroupGetUsers(null, "Domain Admins", 0, out bufPtr, -1, out entriesRead, out totalEntries, ref resumeHandle);
                if ((status == 0 || status == 234) && bufPtr != IntPtr.Zero)
                {
                    IntPtr currentPtr = bufPtr;
                    for (int i = 0; i < entriesRead; i++)
                    {
                        GROUP_USERS_INFO_0 member = (GROUP_USERS_INFO_0)Marshal.PtrToStructure(currentPtr, typeof(GROUP_USERS_INFO_0));
                        if (!string.IsNullOrEmpty(member.grui0_name))
                        {
                            admins.Add(member.grui0_name);
                        }
                        currentPtr = (IntPtr)((long)currentPtr + Marshal.SizeOf(typeof(GROUP_USERS_INFO_0)));
                    }
                }
            }
            catch { }
            finally
            {
                if (bufPtr != IntPtr.Zero)
                {
                    NetApiBufferFree(bufPtr);
                    bufPtr = IntPtr.Zero;
                }
            }

            // 2. Fallback to local Administrators group if standalone machine
            if (admins.Count == 0)
            {
                try
                {
                    resumeHandle = 0;
                    int status = NetLocalGroupGetMembers(null, "Administrators", 0, out bufPtr, -1, out entriesRead, out totalEntries, ref resumeHandle);
                    if ((status == 0 || status == 234) && bufPtr != IntPtr.Zero)
                    {
                        IntPtr currentPtr = bufPtr;
                        for (int i = 0; i < entriesRead; i++)
                        {
                            LOCALGROUP_MEMBERS_INFO_0 member = (LOCALGROUP_MEMBERS_INFO_0)Marshal.PtrToStructure(currentPtr, typeof(LOCALGROUP_MEMBERS_INFO_0));
                            if (!string.IsNullOrEmpty(member.lgrmi0_name))
                            {
                                string name = member.lgrmi0_name;
                                int slash = name.LastIndexOf('\\');
                                if (slash >= 0) name = name.Substring(slash + 1);
                                admins.Add(name);
                            }
                            currentPtr = (IntPtr)((long)currentPtr + Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_0)));
                        }
                    }
                }
                catch { }
                finally
                {
                    if (bufPtr != IntPtr.Zero) NetApiBufferFree(bufPtr);
                }
            }

            return admins;
        }

        // ====================================================================
        // 2. SECURITY REGISTRY AUDITING
        // ====================================================================
        struct RegistryAudit
        {
            public int EnableFirewall;
            public int UserAuthentication;
            public int RunAsPPL;
        }

        static RegistryAudit AuditSecurityRegistry()
        {
            RegistryAudit audit = new RegistryAudit();

            // 1. Firewall StandardProfile / DomainProfile
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"))
                {
                    if (key != null) audit.EnableFirewall = Convert.ToInt32(key.GetValue("EnableFirewall", 0));
                }
                if (audit.EnableFirewall == 0)
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"))
                    {
                        if (key != null && Convert.ToInt32(key.GetValue("EnableFirewall", 0)) == 1)
                            audit.EnableFirewall = 1;
                    }
                }
            }
            catch { }

            // 2. RDP NLA
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"))
                {
                    if (key != null) audit.UserAuthentication = Convert.ToInt32(key.GetValue("UserAuthentication", 0));
                }
            }
            catch { }

            // 3. LSA RunAsPPL
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa"))
                {
                    if (key != null) audit.RunAsPPL = Convert.ToInt32(key.GetValue("RunAsPPL", 0));
                }
            }
            catch { }

            return audit;
        }

        // ====================================================================
        // 2B. AUTOSTART RUN/RUNONCE & USER LOGON/LOGOFF AUDITING
        // ====================================================================
        public struct RunKeyEntry
        {
            public string Location;
            public string Name;
            public string Command;
        }

        public struct WinlogonAudit
        {
            public string Userinit;
            public string Shell;
            public string LogonScript;
            public List<string> LogonLogoffScripts;
        }

        static readonly HashSet<string> BenignRunNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "vmware user process", "vmware tools", "vboxtray", "vboxclient", "securityhealth", "securityhealthsystray"
        };

        static List<RunKeyEntry> AuditRunKeys()
        {
            List<RunKeyEntry> entries = new List<RunKeyEntry>();
            string[] subKeys = new string[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"Software\Microsoft\Windows\CurrentVersion\RunServices",
                @"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            };

            foreach (string sub in subKeys)
            {
                // 1. HKLM
                try
                {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(sub))
                    {
                        if (k != null)
                        {
                            foreach (string valName in k.GetValueNames())
                            {
                                object val = k.GetValue(valName);
                                if (val != null)
                                {
                                    entries.Add(new RunKeyEntry
                                    {
                                        Location = @"HKLM\" + sub,
                                        Name = string.IsNullOrEmpty(valName) ? "(Default)" : valName,
                                        Command = val.ToString()
                                    });
                                }
                            }
                        }
                    }
                }
                catch { }

                // 2. HKCU
                try
                {
                    using (RegistryKey k = Registry.CurrentUser.OpenSubKey(sub))
                    {
                        if (k != null)
                        {
                            foreach (string valName in k.GetValueNames())
                            {
                                object val = k.GetValue(valName);
                                if (val != null)
                                {
                                    entries.Add(new RunKeyEntry
                                    {
                                        Location = @"HKCU\" + sub,
                                        Name = string.IsNullOrEmpty(valName) ? "(Default)" : valName,
                                        Command = val.ToString()
                                    });
                                }
                            }
                        }
                    }
                }
                catch { }
            }

            return entries;
        }

        static WinlogonAudit AuditWinlogon()
        {
            WinlogonAudit audit = new WinlogonAudit();
            audit.Userinit = "C:\\Windows\\system32\\userinit.exe,";
            audit.Shell = "explorer.exe";
            audit.LogonScript = "";
            audit.LogonLogoffScripts = new List<string>();

            // 1. HKLM Winlogon Userinit & Shell (MITRE T1547.004)
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
                {
                    if (k != null)
                    {
                        object u = k.GetValue("Userinit");
                        if (u != null) audit.Userinit = u.ToString();
                        object s = k.GetValue("Shell");
                        if (s != null) audit.Shell = s.ToString();
                        object tm = k.GetValue("Taskman");
                        if (tm != null && !string.IsNullOrEmpty(tm.ToString()))
                        {
                            audit.LogonLogoffScripts.Add("Winlogon Taskman: " + tm.ToString());
                        }
                    }
                }
            }
            catch { }

            // 2. Logon Script (UserInitMprLogonScript) in HKCU & HKLM Environment (MITRE T1037.001)
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Environment"))
                {
                    if (k != null)
                    {
                        object s = k.GetValue("UserInitMprLogonScript");
                        if (s != null && !string.IsNullOrEmpty(s.ToString()))
                            audit.LogonScript = s.ToString();
                    }
                }
            }
            catch { }

            if (string.IsNullOrEmpty(audit.LogonScript))
            {
                try
                {
                    using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))
                    {
                        if (k != null)
                        {
                            object s = k.GetValue("UserInitMprLogonScript");
                            if (s != null && !string.IsNullOrEmpty(s.ToString()))
                                audit.LogonScript = s.ToString();
                        }
                    }
                }
                catch { }
            }

            // 3. Group Policy Logon / Logoff scripts (MITRE T1037)
            string[] gpPaths = new string[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon",
                @"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff",
                @"Software\Policies\Microsoft\Windows\System\Scripts\Logon",
                @"Software\Policies\Microsoft\Windows\System\Scripts\Logoff"
            };

            foreach (string gp in gpPaths)
            {
                AuditGpKey(Registry.LocalMachine, @"HKLM\" + gp, audit.LogonLogoffScripts);
                AuditGpKey(Registry.CurrentUser, @"HKCU\" + gp, audit.LogonLogoffScripts);
            }

            return audit;
        }

        static void AuditGpKey(RegistryKey root, string fullSubKey, List<string> output)
        {
            try
            {
                string rel = fullSubKey.Substring(fullSubKey.IndexOf('\\') + 1);
                using (RegistryKey baseKey = root.OpenSubKey(rel))
                {
                    if (baseKey != null)
                    {
                        foreach (string subName in baseKey.GetSubKeyNames())
                        {
                            using (RegistryKey sub = baseKey.OpenSubKey(subName))
                            {
                                if (sub != null)
                                {
                                    foreach (string item in sub.GetSubKeyNames())
                                    {
                                        using (RegistryKey itemKey = sub.OpenSubKey(item))
                                        {
                                            if (itemKey != null)
                                            {
                                                object script = itemKey.GetValue("Script");
                                                object parameters = itemKey.GetValue("Parameters");
                                                if (script != null)
                                                {
                                                    string desc = fullSubKey + " -> " + script.ToString();
                                                    if (parameters != null && !string.IsNullOrEmpty(parameters.ToString()))
                                                        desc += " " + parameters.ToString();
                                                    output.Add(desc);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        // ====================================================================
        // 3. DUAL-PROCESS MUTUAL WATCHDOG PERSISTENCE
        // ====================================================================
        static int MaintainTwinWatchdog()
        {
            int currentPid = Process.GetCurrentProcess().Id;
            string currentExePath = Process.GetCurrentProcess().MainModule.FileName;
            string currentDir = Path.GetDirectoryName(currentExePath);

            string companionExeName = (TwinIdentity == "alpha") ? "agent_alpha.exe" : "agent_bravo.exe";
            string companionFlag = (TwinIdentity == "alpha") ? "-alpha" : "-bravo";
            string companionFullPath = Path.Combine(currentDir, companionExeName);

            // Find twin process
            string targetProcessName = Path.GetFileNameWithoutExtension(companionExeName);
            Process[] processes = Process.GetProcessesByName(targetProcessName);
            int twinPid = 0;

            foreach (var p in processes)
            {
                if (p.Id != currentPid)
                {
                    twinPid = p.Id;
                    break;
                }
            }

            // Fallback: check processes with current exe name
            if (twinPid == 0)
            {
                string selfName = Path.GetFileNameWithoutExtension(currentExePath);
                Process[] sameName = Process.GetProcessesByName(selfName);
                foreach (var p in sameName)
                {
                    if (p.Id != currentPid)
                    {
                        twinPid = p.Id;
                        break;
                    }
                }
            }

            // If twin is dead, re-spawn immediately
            if (twinPid == 0)
            {
                if (DebugMode) Console.WriteLine("[WATCHDOG] Twin ({0}) missing! Re-spawning immediately...", TwinIdentity);

                if (!File.Exists(companionFullPath))
                {
                    try { File.Copy(currentExePath, companionFullPath, true); } catch { }
                }

                string targetExe = File.Exists(companionFullPath) ? companionFullPath : currentExePath;

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = targetExe;
                psi.Arguments = string.Format("{0} -server {1} -port {2}", companionFlag, ServerHost, ServerPort);
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.UseShellExecute = false;

                try
                {
                    Process spawned = Process.Start(psi);
                    if (spawned != null)
                    {
                        twinPid = spawned.Id;
                        if (DebugMode) Console.WriteLine("[WATCHDOG] Successfully revived twin PID: {0}", twinPid);
                    }
                }
                catch (Exception ex)
                {
                    if (DebugMode) Console.WriteLine("[WATCHDOG] Failed to spawn twin: " + ex.Message);
                }
            }
            else
            {
                if (DebugMode) Console.WriteLine("[WATCHDOG] Twin ({0}) is healthy with PID: {1}", TwinIdentity, twinPid);
            }

            return twinPid;
        }

        // ====================================================================
        // 4. JSON PACKAGING & HTTP TELEMETRY EXFILTRATION
        // ====================================================================
        static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            StringBuilder sb = new StringBuilder();
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '\"': sb.Append("\\\""); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 32)
                            sb.AppendFormat("\\u{0:x4}", (int)c);
                        else
                            sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        static string BuildJson(int twinPid, List<string> users, List<string> admins, RegistryAudit reg, List<RunKeyEntry> runKeys, WinlogonAudit winlogon)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{\n");
            sb.AppendFormat("  \"agent_identity\": \"{0}\",\n", EscapeJson(Identity));
            sb.AppendFormat("  \"hostname\": \"{0}\",\n", EscapeJson(Environment.MachineName));
            sb.AppendFormat("  \"twin_pid\": {0},\n", twinPid);
            sb.AppendFormat("  \"timestamp\": {0},\n", (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds);

            // Users
            sb.Append("  \"users\": [");
            for (int i = 0; i < users.Count; i++)
            {
                sb.AppendFormat("\"{0}\"", EscapeJson(users[i]));
                if (i + 1 < users.Count) sb.Append(", ");
            }
            sb.Append("],\n");

            // Admins
            sb.Append("  \"domain_admins\": [");
            for (int i = 0; i < admins.Count; i++)
            {
                sb.AppendFormat("\"{0}\"", EscapeJson(admins[i]));
                if (i + 1 < admins.Count) sb.Append(", ");
            }
            sb.Append("],\n");

            // Registry
            sb.Append("  \"registry\": {\n");
            sb.AppendFormat("    \"EnableFirewall\": {0},\n", reg.EnableFirewall);
            sb.AppendFormat("    \"UserAuthentication\": {0},\n", reg.UserAuthentication);
            sb.AppendFormat("    \"RunAsPPL\": {0}\n", reg.RunAsPPL);
            sb.Append("  },\n");

            // Run & RunOnce Keys
            sb.Append("  \"run_keys\": [\n");
            for (int i = 0; i < runKeys.Count; i++)
            {
                sb.Append("    {\n");
                sb.AppendFormat("      \"location\": \"{0}\",\n", EscapeJson(runKeys[i].Location));
                sb.AppendFormat("      \"name\": \"{0}\",\n", EscapeJson(runKeys[i].Name));
                sb.AppendFormat("      \"command\": \"{0}\"\n", EscapeJson(runKeys[i].Command));
                sb.Append("    }");
                if (i + 1 < runKeys.Count) sb.Append(",");
                sb.Append("\n");
            }
            sb.Append("  ],\n");

            // Winlogon & Logon/Logoff Scripts
            sb.Append("  \"winlogon\": {\n");
            sb.AppendFormat("    \"Userinit\": \"{0}\",\n", EscapeJson(winlogon.Userinit));
            sb.AppendFormat("    \"Shell\": \"{0}\",\n", EscapeJson(winlogon.Shell));
            sb.AppendFormat("    \"LogonScript\": \"{0}\",\n", EscapeJson(winlogon.LogonScript));
            sb.Append("    \"LogonLogoffScripts\": [");
            if (winlogon.LogonLogoffScripts != null)
            {
                for (int i = 0; i < winlogon.LogonLogoffScripts.Count; i++)
                {
                    sb.AppendFormat("\"{0}\"", EscapeJson(winlogon.LogonLogoffScripts[i]));
                    if (i + 1 < winlogon.LogonLogoffScripts.Count) sb.Append(", ");
                }
            }
            sb.Append("]\n");
            sb.Append("  }\n");
            sb.Append("}");

            return sb.ToString();
        }

        static string LastError = null;

        static bool ExfiltrateTelemetry(string jsonPayload)
        {
            try
            {
                string url = string.Format("http://{0}:{1}{2}", ServerHost, ServerPort, Endpoint);
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "POST";
                req.ContentType = "application/json";
                req.Timeout = 5000;

                byte[] data = Encoding.UTF8.GetBytes(jsonPayload);
                req.ContentLength = data.Length;

                using (Stream stream = req.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    LastError = null;
                    return (resp.StatusCode == HttpStatusCode.OK);
                }
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                return false;
            }
        }

        // ====================================================================
        // OFFLINE LOCAL TRIAGE REPORT (READABLE CONSOLE FALLBACK)
        // ====================================================================
        static void PrintOfflineTriageReport(int twinPid, List<string> users, List<string> admins, RegistryAudit reg, List<RunKeyEntry> runKeys, WinlogonAudit winlogon, string failureReason)
        {
            // Golden state baseline definitions
            HashSet<string> baselineUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Administrator", "Guest", "krbtgt",
                "BlueTeamLead", "BlueTeamAdmin1", "BlueTeamAdmin2", "ScoreUser_AD"
            };

            HashSet<string> baselineAdmins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Administrator", "BlueTeamLead"
            };

            List<string> rogueAdmins = new List<string>();
            foreach (var a in admins)
            {
                if (!baselineAdmins.Contains(a)) rogueAdmins.Add(a);
            }

            List<string> rogueUsers = new List<string>();
            foreach (var u in users)
            {
                if (!baselineUsers.Contains(u)) rogueUsers.Add(u);
            }

            // Filter suspicious Run / RunOnce autostart keys (excluding benign VM tools)
            List<RunKeyEntry> rogueRunKeys = new List<RunKeyEntry>();
            foreach (var r in runKeys)
            {
                string nameLower = (r.Name ?? "").Trim().ToLower();
                string cmdLower = (r.Command ?? "").Trim().ToLower();
                if (BenignRunNames.Contains(nameLower) || cmdLower.Contains("vmtoolsd.exe") || cmdLower.Contains("vboxtray.exe"))
                    continue;
                rogueRunKeys.Add(r);
            }

            // Winlogon & Logon/Logoff Scripts checks
            string uInit = (winlogon.Userinit ?? "").Trim();
            bool isUserinitClean = (uInit.Equals("C:\\Windows\\system32\\userinit.exe,", StringComparison.OrdinalIgnoreCase) ||
                                    uInit.Equals("C:\\Windows\\system32\\userinit.exe", StringComparison.OrdinalIgnoreCase));
            string shellVal = (winlogon.Shell ?? "").Trim();
            bool isShellClean = (shellVal.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(shellVal));
            bool hasLogonScript = !string.IsNullOrEmpty(winlogon.LogonScript);
            bool hasGpScripts = (winlogon.LogonLogoffScripts != null && winlogon.LogonLogoffScripts.Count > 0);

            // Calculate AD Security Health Score
            int score = 100;
            if (rogueAdmins.Count > 0) score -= 40;
            if (reg.EnableFirewall != 1) score -= 30;
            if (reg.UserAuthentication != 1 || reg.RunAsPPL != 1) score -= 20;
            if (rogueRunKeys.Count > 0) score -= Math.Min(25, rogueRunKeys.Count * 15);
            if (!isUserinitClean) score -= 30;
            if (!isShellClean) score -= 25;
            if (hasLogonScript) score -= 20;
            if (hasGpScripts) score -= Math.Min(25, winlogon.LogonLogoffScripts.Count * 15);
            
            int rogueStandard = 0;
            foreach (var u in rogueUsers)
            {
                if (!rogueAdmins.Contains(u)) rogueStandard++;
            }
            if (rogueStandard > 0) score -= Math.Min(20, rogueStandard * 10);
            score = Math.Max(0, Math.Min(100, score));

            Console.WriteLine();
            Console.WriteLine("================================================================================");
            Console.WriteLine("  [OFFLINE LOCAL TRIAGE CONSOLE] - HOST DASHBOARD UNREACHABLE");
            Console.WriteLine("  Target Address : http://{0}:{1}{2}", ServerHost, ServerPort, Endpoint);
            if (!string.IsNullOrEmpty(failureReason))
                Console.WriteLine("  Network Status : {0}", failureReason);
            Console.WriteLine("  Local Identity : {0} (Twin PID: {1}) | Host: {2}", Identity.ToUpper(), twinPid, Environment.MachineName);
            Console.WriteLine("================================================================================");

            if (score == 100)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  >>> AD HEALTH SCORE : 100% [GOLDEN STATE COMPLIANT — ALL DEFENSES VERIFIED] <<<");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  >>> AD HEALTH SCORE : {0}% [CRITICAL INTEGRITY BREACH DETECTED AT MINUTE-0] <<<", score);
                Console.ResetColor();
            }

            Console.WriteLine("--------------------------------------------------------------------------------");
            Console.WriteLine("  1. ACTIVE DIRECTORY ACCOUNT AUDIT:");
            Console.WriteLine("     Total Accounts Found : {0}", users.Count);
            if (rogueUsers.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] ROGUE ACCOUNTS ({0}) : {1}", rogueUsers.Count, string.Join(", ", rogueUsers));
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] All accounts match pristine Golden State whitelist.");
                Console.ResetColor();
            }

            Console.WriteLine();
            Console.WriteLine("  2. PRIVILEGED ACCESS AUDIT (DOMAIN ADMINS):");
            Console.WriteLine("     Total Admins Found   : {0}", admins.Count);
            if (rogueAdmins.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] ROGUE DOMAIN ADMINS : {0} (PRIVILEGE ESCALATION!)", string.Join(", ", rogueAdmins));
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] Domain Admins matches pristine baseline: " + string.Join(", ", baselineAdmins));
                Console.ResetColor();
            }

            Console.WriteLine();
            Console.WriteLine("  3. SECURITY REGISTRY HARDENING AUDIT:");
            if (reg.EnableFirewall == 1)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] Windows Firewall     : 1 [ENFORCED]");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] Windows Firewall     : 0 [DISABLED - HOST EXPOSED]");
                Console.ResetColor();
            }

            if (reg.UserAuthentication == 1)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] RDP Network Level NLA: 1 [ENFORCED]");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("     [!] RDP Network Level NLA: 0 [DISABLED - PRE-AUTH EXPLOITS]");
                Console.ResetColor();
            }

            if (reg.RunAsPPL == 1)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] LSA RunAsPPL Guard   : 1 [ENFORCED]");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] LSA RunAsPPL Guard   : 0 [DISABLED - MIMIKATZ DUMP TARGET]");
                Console.ResetColor();
            }

            Console.WriteLine();
            Console.WriteLine("  4. AUTOSTART PERSISTENCE AUDIT (RUN & RUNONCE KEYS - MITRE T1547.001):");
            Console.WriteLine("     Total Autostart Entries  : {0}", runKeys.Count);
            if (rogueRunKeys.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] ROGUE AUTOSTART KEYS ({0}) DETECTED:", rogueRunKeys.Count);
                foreach (var rk in rogueRunKeys)
                {
                    Console.WriteLine("         • [{0}] '{1}' -> \"{2}\"", rk.Location, rk.Name, rk.Command);
                }
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] Clean (Zero unauthorized Run / RunOnce autostart keys).");
                Console.ResetColor();
            }

            Console.WriteLine();
            Console.WriteLine("  5. WINLOGON & USER LOGON/LOGOFF AUDIT (MITRE T1547.004 / T1037):");
            if (isUserinitClean)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] Winlogon Userinit    : Enforced ({0})", uInit);
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] Winlogon Userinit    : HIJACKED! ({0})", uInit);
                Console.ResetColor();
            }

            if (isShellClean)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] Winlogon Shell       : Enforced ({0})", string.IsNullOrEmpty(shellVal) ? "explorer.exe" : shellVal);
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] Winlogon Shell       : HIJACKED! ({0})", shellVal);
                Console.ResetColor();
            }

            if (!hasLogonScript)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] User Logon Script    : None (Pristine)");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] User Logon Script    : ROGUE SCRIPT! ({0})", winlogon.LogonScript);
                Console.ResetColor();
            }

            if (hasGpScripts)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("     [!] GPO Scripts Detected : {0}", string.Join("; ", winlogon.LogonLogoffScripts));
                Console.ResetColor();
            }

            if (score < 100)
            {
                Console.WriteLine();
                Console.WriteLine("  6. RECOMMENDED EMERGENCY REMEDIATION (POWERSHELL):");
                if (rogueAdmins.Count > 0)
                {
                    foreach (var a in rogueAdmins)
                    {
                        Console.WriteLine("     Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"{0}\" -Confirm:$false", a);
                        Console.WriteLine("     Disable-ADAccount -Identity \"{0}\"", a);
                    }
                }
                if (reg.EnableFirewall != 1)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\" -Name \"EnableFirewall\" -Value 1");
                    Console.WriteLine("     Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True");
                }
                if (reg.RunAsPPL != 1)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" -Name \"RunAsPPL\" -Value 1");
                }
                if (reg.UserAuthentication != 1)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name \"UserAuthentication\" -Value 1");
                }
                if (rogueRunKeys.Count > 0)
                {
                    foreach (var rk in rogueRunKeys)
                    {
                        Console.WriteLine("     Remove-ItemProperty -Path \"Registry::{0}\" -Name \"{1}\" -Force", rk.Location, rk.Name);
                    }
                }
                if (!isUserinitClean)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Userinit\" -Value \"C:\\Windows\\system32\\userinit.exe,\"");
                }
                if (!isShellClean)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Shell\" -Value \"explorer.exe\"");
                }
                if (hasLogonScript)
                {
                    Console.WriteLine("     Remove-ItemProperty -Path \"HKCU:\\Environment\" -Name \"UserInitMprLogonScript\" -Force");
                    Console.WriteLine("     Remove-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" -Name \"UserInitMprLogonScript\" -Force -ErrorAction SilentlyContinue");
                }
            }

            Console.WriteLine("================================================================================");
            if (ServerHost == "127.0.0.1" || ServerHost == "localhost")
            {
                Console.WriteLine("  [TIP] Currently targeting 127.0.0.1. To exfiltrate to your host dashboard:");
                Console.WriteLine("        agent_alpha.exe -alpha -server <HOST_IP> -port 8000 -debug");
                Console.WriteLine("================================================================================");
            }
            Console.WriteLine();
        }

        // ====================================================================
        // MAIN ENTRYPOINT
        // ====================================================================
        static void Main(string[] args)
        {
            // Always attempt to attach to parent console if invoked from cmd/powershell
            if (!AttachConsole(-1))
            {
                if (DebugMode) AllocConsole();
            }

            // Parse CLI flags
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].ToLower();
                if (a == "-alpha") { Identity = "alpha"; TwinIdentity = "bravo"; }
                else if (a == "-bravo") { Identity = "bravo"; TwinIdentity = "alpha"; }
                else if (a == "-server" && i + 1 < args.Length) ServerHost = args[++i];
                else if (a == "-port" && i + 1 < args.Length) int.TryParse(args[++i], out ServerPort);
                else if (a == "-interval" && i + 1 < args.Length) int.TryParse(args[++i], out IntervalSec);
                else if (a == "-debug") DebugMode = true;
            }

            if (DebugMode)
            {
                Console.WriteLine("=======================================================");
                Console.WriteLine("  AD WATCHDOG NATIVE ENGINE (ACTIVE DIRECTORY / DC)");
                Console.WriteLine("=======================================================");
                Console.WriteLine("[+] Agent Identity : " + Identity);
                Console.WriteLine("[+] Twin Companion : " + TwinIdentity);
                Console.WriteLine("[+] Target Server  : http://" + ServerHost + ":" + ServerPort + Endpoint);
                Console.WriteLine("[+] Polling Interval: " + IntervalSec + "s (" + (IntervalSec / 60) + " min)");
                Console.WriteLine("=======================================================");
            }

            while (true)
            {
                // 1. Maintain mutual watchdog persistence
                int twinPid = MaintainTwinWatchdog();

                // 2. Perform native user & group audit
                List<string> users = QueryActiveDirectoryUsers();
                List<string> admins = QueryDomainAdmins();

                // 3. Perform security registry audit
                RegistryAudit reg = AuditSecurityRegistry();

                // 4. Perform autostart Run/RunOnce & Winlogon / logon script audit
                List<RunKeyEntry> runKeys = AuditRunKeys();
                WinlogonAudit winlogon = AuditWinlogon();

                // 5. Build JSON
                string jsonPayload = BuildJson(twinPid, users, admins, reg, runKeys, winlogon);

                if (DebugMode)
                {
                    Console.WriteLine("[*] Audited {0} users, {1} admins. Reg: FW={2}, NLA={3}, PPL={4}. RunKeys={5}, LogonScripts={6}",
                        users.Count, admins.Count, reg.EnableFirewall, reg.UserAuthentication, reg.RunAsPPL, runKeys.Count, winlogon.LogonScript);
                    Console.WriteLine("[+] Exfiltrating to http://{0}:{1}{2}...", ServerHost, ServerPort, Endpoint);
                }

                // 6. Exfiltrate
                bool ok = ExfiltrateTelemetry(jsonPayload);
                if (ok)
                {
                    if (DebugMode)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[*] HTTP POST Result: [✔] 200 OK (Telemetry Ingested by Central Server)");
                        Console.ResetColor();
                        Console.WriteLine("-------------------------------------------------------");
                    }
                }
                else
                {
                    // UNABLE TO CONNECT TO HOST MACHINE -> OUTPUT READABLE TRIAGE DIRECTLY TO CONSOLE
                    PrintOfflineTriageReport(twinPid, users, admins, reg, runKeys, winlogon, LastError);
                }

                // 7. Sleep for 5 minutes (300 seconds)
                if (DebugMode || !ok)
                {
                    Console.WriteLine("[*] Sleeping for {0} seconds ({1} minutes) before next audit round...", IntervalSec, IntervalSec / 60);
                }
                Thread.Sleep(IntervalSec * 1000);
            }
        }
    }
}
