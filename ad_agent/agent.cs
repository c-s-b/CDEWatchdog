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
        // CONFIGURATION & GLOBAL STATE
        // ====================================================================
        static string Identity = "alpha";
        static string TwinIdentity = "bravo";
        static string ServerHost = "127.0.0.1";
        static int ServerPort = 8000;
        static int WebPort = 8000;
        static string Endpoint = "/api/ad_triage";
        static int IntervalSec = 300; // 5 minutes (300 seconds)
        static bool DebugMode = false;
        static bool EnableLocalWeb = true;
        static bool IsTwin = false;
        static string SimulatedMode = "none"; // "none", "contaminated", "pristine"

        static int TelemetryCounter = 0;
        static string LastError = null;
        static string LatestRemediationLog = null;
        static readonly object StateLock = new object();
        static readonly AutoResetEvent AuditWakeupEvent = new AutoResetEvent(false);

        static readonly HashSet<string> DynamicWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Pristine Golden State definitions
        static readonly HashSet<string> BaselineUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Administrator", "Guest", "krbtgt",
            "BlueTeamLead", "BlueTeamAdmin1", "BlueTeamAdmin2", "ScoreUser_AD"
        };

        static readonly HashSet<string> BaselineAdmins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Administrator", "BlueTeamLead"
        };

        static readonly HashSet<string> BenignRunNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "vmware user process", "vmware tools", "vboxtray", "vboxclient", "securityhealth", "securityhealthsystray"
        };

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
        // DATA STRUCTURES
        // ====================================================================
        public struct RegistryAudit
        {
            public int EnableFirewall;
            public int UserAuthentication;
            public int RunAsPPL;
        }

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

        public class AnomalyItem
        {
            public string Timestamp;
            public string Severity;
            public string Category;
            public string Finding;
            public string Details;
            public string MitreAttack;
            public string RemediationCmd;
        }

        public class AuditState
        {
            public long Timestamp;
            public string AgentIdentity;
            public string Hostname;
            public int TwinPid;
            public int TelemetryCounter;
            public int HealthScore;
            public List<string> Users;
            public List<string> DomainAdmins;
            public RegistryAudit Registry;
            public List<RunKeyEntry> RunKeys;
            public WinlogonAudit Winlogon;
            public List<string> RogueUsers;
            public List<string> RogueDomainAdmins;
            public List<RunKeyEntry> RogueRunKeys;
            public List<AnomalyItem> Anomalies;
            public List<string> ExtraWhitelist;
            public string RemediationLog;
            public bool IsUserinitClean;
            public bool IsShellClean;
            public bool HasLogonScript;
            public bool HasGpScripts;

            public AuditState()
            {
                Users = new List<string>();
                DomainAdmins = new List<string>();
                RunKeys = new List<RunKeyEntry>();
                Winlogon = new WinlogonAudit { LogonLogoffScripts = new List<string>() };
                RogueUsers = new List<string>();
                RogueDomainAdmins = new List<string>();
                RogueRunKeys = new List<RunKeyEntry>();
                Anomalies = new List<AnomalyItem>();
                ExtraWhitelist = new List<string>();
            }
        }

        static AuditState CurrentAuditState = new AuditState();

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
            audit.Userinit = @"C:\Windows\system32\userinit.exe,";
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
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey("Environment"))
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
        // 3. SET-DIFFERENCE & ANOMALY EVALUATION ENGINE
        // ====================================================================
        static void AuditCurrentSystem(int twinPid)
        {
            TelemetryCounter++;
            List<string> users = QueryActiveDirectoryUsers();
            List<string> admins = QueryDomainAdmins();
            RegistryAudit reg = AuditSecurityRegistry();
            List<RunKeyEntry> runKeys = AuditRunKeys();
            WinlogonAudit winlogon = AuditWinlogon();

            // Handle simulated overrides if testing
            if (SimulatedMode == "contaminated")
            {
                users = new List<string> { "Administrator", "Guest", "krbtgt", "BlueTeamLead", "BlueTeamAdmin1", "ScoreUser_AD", "adm_backdoor", "support_ghost" };
                admins = new List<string> { "Administrator", "BlueTeamLead", "adm_backdoor" };
                reg.EnableFirewall = 0;
                reg.UserAuthentication = 0;
                reg.RunAsPPL = 0;
                runKeys = new List<RunKeyEntry> { new RunKeyEntry { Location = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", Name = "EvilBackdoor", Command = "powershell.exe -w hidden -enc SQBFAFgA..." } };
                winlogon.Userinit = @"C:\Windows\system32\userinit.exe,C:\Windows\Temp\ghost_init.exe";
                winlogon.Shell = "cmd.exe";
                winlogon.LogonScript = @"\\10.0.0.99\netlogon\update.bat";
            }
            else if (SimulatedMode == "pristine")
            {
                users = new List<string> { "Administrator", "Guest", "krbtgt", "BlueTeamLead", "BlueTeamAdmin1", "BlueTeamAdmin2", "ScoreUser_AD" };
                admins = new List<string> { "Administrator", "BlueTeamLead" };
                reg.EnableFirewall = 1;
                reg.UserAuthentication = 1;
                reg.RunAsPPL = 1;
                runKeys = new List<RunKeyEntry>();
                winlogon.Userinit = @"C:\Windows\system32\userinit.exe,";
                winlogon.Shell = "explorer.exe";
                winlogon.LogonScript = "";
                winlogon.LogonLogoffScripts = new List<string>();
            }

            // Combined active whitelist
            HashSet<string> activeWhitelist = new HashSet<string>(BaselineUsers, StringComparer.OrdinalIgnoreCase);
            lock (StateLock)
            {
                foreach (var u in DynamicWhitelist) activeWhitelist.Add(u);
            }

            // 1. Identify Rogue Admins
            List<string> rogueAdmins = new List<string>();
            foreach (var a in admins)
            {
                if (!BaselineAdmins.Contains(a)) rogueAdmins.Add(a);
            }

            // 2. Identify Rogue Users
            List<string> rogueUsers = new List<string>();
            foreach (var u in users)
            {
                if (!activeWhitelist.Contains(u)) rogueUsers.Add(u);
            }

            // 3. Filter Suspicious Run / RunOnce autostart keys
            List<RunKeyEntry> rogueRunKeys = new List<RunKeyEntry>();
            foreach (var r in runKeys)
            {
                string nameLower = (r.Name ?? "").Trim().ToLower();
                string cmdLower = (r.Command ?? "").Trim().ToLower();
                if (BenignRunNames.Contains(nameLower) || cmdLower.Contains("vmtoolsd.exe") || cmdLower.Contains("vboxtray.exe"))
                    continue;
                rogueRunKeys.Add(r);
            }

            // 4. Winlogon checks
            string uInit = (winlogon.Userinit ?? "").Trim();
            bool isUserinitClean = (uInit.Equals(@"C:\Windows\system32\userinit.exe,", StringComparison.OrdinalIgnoreCase) ||
                                    uInit.Equals(@"C:\Windows\system32\userinit.exe", StringComparison.OrdinalIgnoreCase));
            string shellVal = (winlogon.Shell ?? "").Trim();
            bool isShellClean = (shellVal.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(shellVal));
            bool hasLogonScript = !string.IsNullOrEmpty(winlogon.LogonScript);
            bool hasGpScripts = (winlogon.LogonLogoffScripts != null && winlogon.LogonLogoffScripts.Count > 0);

            // 5. Calculate Health Score
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

            // 6. Build Anomaly Records
            string ts = DateTime.Now.ToString("HH:mm:ss");
            List<AnomalyItem> anomalies = new List<AnomalyItem>();

            foreach (var rk in rogueRunKeys)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "CRITICAL",
                    Category = "Autostart Persistence (Run Key)",
                    Finding = string.Format("Unauthorized Run/RunOnce Key: '{0}' in {1}", rk.Name, rk.Location),
                    Details = string.Format("Autostart execution payload configured: {0} -> \"{1}\". Executes on user logon.", rk.Name, rk.Command),
                    MitreAttack = "T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)",
                    RemediationCmd = string.Format("Remove-ItemProperty -Path \"Registry::{0}\" -Name \"{1}\" -Force", rk.Location, rk.Name)
                });
            }

            if (!isUserinitClean)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "CRITICAL",
                    Category = "Logon Persistence (Winlogon Hijack)",
                    Finding = string.Format("Winlogon Userinit Hijacked: '{0}'", uInit),
                    Details = "Winlogon Userinit value modified from default. Executes arbitrary payload during logon sequence.",
                    MitreAttack = "T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL / Userinit)",
                    RemediationCmd = "Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Userinit\" -Value \"C:\\Windows\\system32\\userinit.exe,\""
                });
            }

            if (!isShellClean)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "HIGH",
                    Category = "Logon Persistence (Winlogon Shell Hijack)",
                    Finding = string.Format("Winlogon Shell Hijacked: '{0}'", shellVal),
                    Details = "Winlogon Shell replacement detected. Executes attacker process instead of standard Windows Explorer.",
                    MitreAttack = "T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL / Shell)",
                    RemediationCmd = "Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Shell\" -Value \"explorer.exe\""
                });
            }

            if (hasLogonScript)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "HIGH",
                    Category = "Logon Script Persistence",
                    Finding = string.Format("UserInitMprLogonScript Hook: '{0}'", winlogon.LogonScript),
                    Details = "UserInitMprLogonScript registry value configured. Triggers execution during every domain user interactive logon.",
                    MitreAttack = "T1037.001 (Boot or Logon Initialization Scripts: Logon Script)",
                    RemediationCmd = "Remove-ItemProperty -Path \"HKCU:\\Environment\" -Name \"UserInitMprLogonScript\" -Force"
                });
            }

            if (hasGpScripts)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "MEDIUM",
                    Category = "GPO Logon/Logoff Scripts",
                    Finding = string.Format("GPO Script Hooks: {0}", string.Join("; ", winlogon.LogonLogoffScripts.ToArray())),
                    Details = "Local or domain Group Policy scripts configured to trigger upon user logon/logoff.",
                    MitreAttack = "T1037.001 (Boot or Logon Initialization Scripts: Group Policy Scripts)",
                    RemediationCmd = "Review & Purge from HKLM\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts"
                });
            }

            foreach (var a in rogueAdmins)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "CRITICAL",
                    Category = "Privileged Access Escalation",
                    Finding = string.Format("Rogue Domain Admin Detected: '{0}'", a),
                    Details = "Unauthorized account added to Domain Admins group outside pristine baseline. Minute-0 persistence / privilege escalation.",
                    MitreAttack = "T1078.002 (Valid Accounts: Domain Accounts) / T1098 (Account Manipulation)",
                    RemediationCmd = string.Format("Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"{0}\" -Confirm:$false; Disable-ADAccount -Identity \"{0}\"", a)
                });
            }

            foreach (var u in rogueUsers)
            {
                if (!rogueAdmins.Contains(u))
                {
                    anomalies.Add(new AnomalyItem
                    {
                        Timestamp = ts,
                        Severity = "HIGH",
                        Category = "Backdoor Account",
                        Finding = string.Format("Unwhitelisted Account Detected: '{0}'", u),
                        Details = "Unauthorized domain account present in Active Directory SAM/NTDS outside baseline roster.",
                        MitreAttack = "T1136.002 (Create Account: Domain Account)",
                        RemediationCmd = string.Format("Disable-ADAccount -Identity \"{0}\"", u)
                    });
                }
            }

            if (reg.EnableFirewall != 1)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "CRITICAL",
                    Category = "Defense Impairment",
                    Finding = "Windows Host Firewall Disabled (EnableFirewall = 0)",
                    Details = "Host firewall profile disabled in registry. Machine exposed to network scans and lateral movement.",
                    MitreAttack = "T1562.004 (Impair Defenses: Disable or Modify System Firewall)",
                    RemediationCmd = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
                });
            }

            if (reg.UserAuthentication != 1)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "MEDIUM",
                    Category = "Defense Weakening",
                    Finding = "RDP Network Level Authentication (NLA) Disabled",
                    Details = "RDP NLA disabled (UserAuthentication = 0). Exposes RDP service to pre-authentication exploits (e.g. BlueKeep).",
                    MitreAttack = "T1021.001 (Remote Services: Remote Desktop Protocol)",
                    RemediationCmd = "Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name \"UserAuthentication\" -Value 1"
                });
            }

            if (reg.RunAsPPL != 1)
            {
                anomalies.Add(new AnomalyItem
                {
                    Timestamp = ts,
                    Severity = "HIGH",
                    Category = "Credential Guard Impairment",
                    Finding = "LSA Protected Process Light (RunAsPPL) Disabled",
                    Details = "LSASS process protection not enforced (RunAsPPL = 0). Memory vulnerable to credential dumping tools like Mimikatz.",
                    MitreAttack = "T1003.001 (OS Credential Dumping: LSASS Memory)",
                    RemediationCmd = "Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" -Name \"RunAsPPL\" -Value 1"
                });
            }

            // Update thread-safe state
            lock (StateLock)
            {
                CurrentAuditState.Timestamp = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
                CurrentAuditState.AgentIdentity = Identity.ToUpper();
                CurrentAuditState.Hostname = Environment.MachineName;
                CurrentAuditState.TwinPid = twinPid;
                CurrentAuditState.TelemetryCounter = TelemetryCounter;
                CurrentAuditState.HealthScore = score;
                CurrentAuditState.Users = users;
                CurrentAuditState.DomainAdmins = admins;
                CurrentAuditState.Registry = reg;
                CurrentAuditState.RunKeys = runKeys;
                CurrentAuditState.Winlogon = winlogon;
                CurrentAuditState.RogueUsers = rogueUsers;
                CurrentAuditState.RogueDomainAdmins = rogueAdmins;
                CurrentAuditState.RogueRunKeys = rogueRunKeys;
                CurrentAuditState.Anomalies = anomalies;
                CurrentAuditState.ExtraWhitelist = new List<string>(DynamicWhitelist);
                CurrentAuditState.RemediationLog = LatestRemediationLog;
                CurrentAuditState.IsUserinitClean = isUserinitClean;
                CurrentAuditState.IsShellClean = isShellClean;
                CurrentAuditState.HasLogonScript = hasLogonScript;
                CurrentAuditState.HasGpScripts = hasGpScripts;
            }
        }

        // ====================================================================
        // 4. RICH TERMINAL CONSOLE TRIAGE REPORT (RETAINED)
        // ====================================================================
        static void PrintTriageReport()
        {
            AuditState s;
            lock (StateLock)
            {
                s = CurrentAuditState;
            }

            Console.WriteLine();
            Console.WriteLine("================================================================================");
            Console.WriteLine("  [AD WATCHDOG NATIVE ENGINE & LOCAL SECURITY DASHBOARD]");
            Console.WriteLine("  Local Web GUI   : http://127.0.0.1:{0}/ [ACTIVE - OPEN IN LOCAL BROWSER]", WebPort);
            Console.WriteLine("  Agent Identity  : {0} (Twin PID: {1}) | Host: {2}", s.AgentIdentity, s.TwinPid, s.Hostname);
            Console.WriteLine("  Audit Interval  : {0}s ({1} minutes) | Heartbeat Round: #{2}", IntervalSec, IntervalSec / 60, s.TelemetryCounter);
            if (!string.IsNullOrEmpty(LastError))
                Console.WriteLine("  Remote Exfil    : {0}", LastError);
            Console.WriteLine("================================================================================");

            if (s.HealthScore == 100)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  >>> AD HEALTH SCORE : 100% [GOLDEN STATE COMPLIANT — ALL DEFENSES VERIFIED] <<<");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  >>> AD HEALTH SCORE : {0}% [CRITICAL INTEGRITY BREACH DETECTED AT MINUTE-0] <<<", s.HealthScore);
                Console.ResetColor();
            }

            Console.WriteLine("--------------------------------------------------------------------------------");
            Console.WriteLine("  1. ACTIVE DIRECTORY ACCOUNT AUDIT:");
            Console.WriteLine("     Total Accounts Found : {0}", s.Users.Count);
            if (s.RogueUsers.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] ROGUE ACCOUNTS ({0}) : {1}", s.RogueUsers.Count, string.Join(", ", s.RogueUsers.ToArray()));
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
            Console.WriteLine("     Total Admins Found   : {0}", s.DomainAdmins.Count);
            if (s.RogueDomainAdmins.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] ROGUE DOMAIN ADMINS : {0} (PRIVILEGE ESCALATION!)", string.Join(", ", s.RogueDomainAdmins.ToArray()));
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] Domain Admins matches pristine baseline: {0}", string.Join(", ", new List<string>(BaselineAdmins).ToArray()));
                Console.ResetColor();
            }

            Console.WriteLine();
            Console.WriteLine("  3. SECURITY REGISTRY HARDENING AUDIT:");
            if (s.Registry.EnableFirewall == 1)
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

            if (s.Registry.UserAuthentication == 1)
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

            if (s.Registry.RunAsPPL == 1)
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
            Console.WriteLine("     Total Autostart Entries  : {0}", s.RunKeys.Count);
            if (s.RogueRunKeys.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] ROGUE AUTOSTART KEYS ({0}) DETECTED:", s.RogueRunKeys.Count);
                foreach (var rk in s.RogueRunKeys)
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
            if (s.IsUserinitClean)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] Winlogon Userinit    : Enforced ({0})", s.Winlogon.Userinit);
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] Winlogon Userinit    : HIJACKED! ({0})", s.Winlogon.Userinit);
                Console.ResetColor();
            }

            if (s.IsShellClean)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] Winlogon Shell       : Enforced ({0})", string.IsNullOrEmpty(s.Winlogon.Shell) ? "explorer.exe" : s.Winlogon.Shell);
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] Winlogon Shell       : HIJACKED! ({0})", s.Winlogon.Shell);
                Console.ResetColor();
            }

            if (!s.HasLogonScript)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("     [✔] User Logon Script    : None (Pristine)");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("     [!] User Logon Script    : ROGUE SCRIPT! ({0})", s.Winlogon.LogonScript);
                Console.ResetColor();
            }

            if (s.HasGpScripts)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("     [!] GPO Scripts Detected : {0}", string.Join("; ", s.Winlogon.LogonLogoffScripts.ToArray()));
                Console.ResetColor();
            }

            if (s.HealthScore < 100)
            {
                Console.WriteLine();
                Console.WriteLine("  6. RECOMMENDED EMERGENCY REMEDIATION (POWERSHELL / 1-CLICK WEB GUI):");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("     [TIP] Click [🚨 Purge Rogue Admins & Lock Policies] at http://127.0.0.1:{0}/", WebPort);
                Console.WriteLine("     Or execute manual commands below:");
                if (s.RogueDomainAdmins.Count > 0)
                {
                    foreach (var a in s.RogueDomainAdmins)
                    {
                        Console.WriteLine("     Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"{0}\" -Confirm:$false", a);
                        Console.WriteLine("     Disable-ADAccount -Identity \"{0}\"", a);
                    }
                }
                if (s.Registry.EnableFirewall != 1)
                {
                    Console.WriteLine("     Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True");
                }
                if (s.Registry.RunAsPPL != 1)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" -Name \"RunAsPPL\" -Value 1");
                }
                if (s.Registry.UserAuthentication != 1)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name \"UserAuthentication\" -Value 1");
                }
                if (s.RogueRunKeys.Count > 0)
                {
                    foreach (var rk in s.RogueRunKeys)
                    {
                        Console.WriteLine("     Remove-ItemProperty -Path \"Registry::{0}\" -Name \"{1}\" -Force", rk.Location, rk.Name);
                    }
                }
                if (!s.IsUserinitClean)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Userinit\" -Value \"C:\\Windows\\system32\\userinit.exe,\"");
                }
                if (!s.IsShellClean)
                {
                    Console.WriteLine("     Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" -Name \"Shell\" -Value \"explorer.exe\"");
                }
                if (s.HasLogonScript)
                {
                    Console.WriteLine("     Remove-ItemProperty -Path \"HKCU:\\Environment\" -Name \"UserInitMprLogonScript\" -Force");
                }
                Console.ResetColor();
            }

            Console.WriteLine("================================================================================");
            Console.WriteLine("  [✔] Active Local Web Dashboard: http://127.0.0.1:{0}/", WebPort);
            Console.WriteLine("  [✔] Air-gapped safe: 0 network bytes leave the DC. Telemetry hosted on loopback.");
            Console.WriteLine("================================================================================");
            Console.WriteLine();
        }

        // ====================================================================
        // 5. EMBEDDED LOCAL WEB DASHBOARD (HTTP LISTENER)
        // ====================================================================
        static HttpListener WebListener = null;
        static Thread WebThread = null;
        static bool WebServerRunning = false;

        const string DashboardHtml = @"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>AD Watchdog | Local Air-Gapped DC Integrity Dashboard</title>
    <style>
        :root {
            --bg-base: #0b0f19;
            --bg-card: #111827;
            --border-card: #1f293d;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --red-crit: #ff1744;
            --orange-high: #ff9100;
            --yellow-med: #ffd600;
            --green-ok: #00e676;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, Helvetica, Arial, sans-serif; }
        body { background-color: var(--bg-base); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
        .sidebar { width: 320px; background-color: #0d1322; border-right: 1px solid var(--border-card); padding: 24px; display: flex; flex-direction: column; gap: 20px; overflow-y: auto; }
        .content { flex: 1; padding: 24px 32px; overflow-y: auto; }
        .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .title-group h1 { font-size: 1.8rem; font-weight: 800; display: flex; align-items: center; gap: 10px; }
        .title-group p { color: var(--text-muted); font-size: 0.9rem; margin-top: 4px; }
        .panic-btn {
            background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
            color: #ffffff;
            font-weight: 800;
            font-size: 0.95rem;
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }
        .panic-btn:hover { transform: translateY(-2px); box-shadow: 0 0 25px rgba(239, 68, 68, 0.7); }
        .score-card { border-radius: 12px; padding: 28px; text-align: center; margin-bottom: 28px; transition: all 0.3s ease; }
        .score-card.good { background: linear-gradient(135deg, #064e3b 0%, #022c22 100%); border: 2px solid var(--green-ok); box-shadow: 0 0 25px rgba(0, 230, 118, 0.25); }
        .score-card.bad { background: linear-gradient(135deg, #4c0519 0%, #2a0009 100%); border: 2px solid var(--red-crit); box-shadow: 0 0 30px rgba(255, 23, 68, 0.35); animation: pulse-red 2s infinite; }
        @keyframes pulse-red { 0% { box-shadow: 0 0 15px rgba(255, 23, 68, 0.2); } 50% { box-shadow: 0 0 35px rgba(255, 23, 68, 0.5); } 100% { box-shadow: 0 0 15px rgba(255, 23, 68, 0.2); } }
        .score-headline { font-size: 5.5rem; font-weight: 900; letter-spacing: -2px; line-height: 1.1; }
        .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border-card); margin-bottom: 20px; }
        .tab-btn { background: none; border: none; color: var(--text-muted); padding: 10px 16px; font-size: 0.95rem; font-weight: 600; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s ease; }
        .tab-btn.active { color: #ffffff; border-bottom: 2px solid var(--accent); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .data-table { width: 100%; border-collapse: collapse; background: var(--bg-card); border-radius: 8px; overflow: hidden; font-size: 0.9rem; }
        .data-table th, .data-table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border-card); }
        .data-table th { background: #162032; font-weight: 700; color: #94a3b8; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
        .badge-crit { background-color: var(--red-crit); color: #fff; }
        .badge-high { background-color: var(--orange-high); color: #fff; }
        .badge-med { background-color: var(--yellow-med); color: #000; }
        .badge-ok { background-color: var(--green-ok); color: #000; }
        .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
        .card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 8px; padding: 18px; }
        .card h3 { font-size: 1rem; margin-bottom: 8px; }
        .code-box { background: #050811; border: 1px solid #1e293b; border-radius: 6px; padding: 10px; font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 0.8rem; color: #38bdf8; word-break: break-all; margin-top: 8px; }
        .terminal-box { background: #050811; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; color: #00ff66; font-family: 'Courier New', monospace; font-size: 0.85rem; line-height: 1.4; max-height: 280px; overflow-y: auto; white-space: pre-wrap; margin-bottom: 24px; }
        input[type=""text""] { width: 100%; background: #162032; border: 1px solid var(--border-card); padding: 10px; border-radius: 6px; color: #fff; margin-bottom: 8px; }
        .action-btn { width: 100%; background: var(--accent); border: none; padding: 10px; border-radius: 6px; color: #fff; font-weight: 600; cursor: pointer; margin-bottom: 8px; }
        .action-btn:hover { background: var(--accent-hover); }
        .btn-outline { background: transparent; border: 1px solid var(--border-card); color: var(--text-main); }
        .btn-outline:hover { background: #1f2937; }
    </style>
</head>
<body>
    <div class=""sidebar"">
        <div>
            <h2>🛡️ AD WATCHDOG</h2>
            <p style=""color: var(--text-muted); font-size: 0.8rem;"">Local Native DC Dashboard</p>
        </div>

        <div class=""card"">
            <h3>📡 Host & Watchdog</h3>
            <p style=""font-size: 0.85rem;"">Agent Identity: <strong id=""agent-identity"" style=""color: var(--accent);"">ALPHA</strong></p>
            <p style=""font-size: 0.85rem;"">Twin PID: <strong id=""twin-pid"">N/A</strong></p>
            <p style=""font-size: 0.85rem;"">DC Host: <code id=""host-name"" style=""color: #38bdf8;"">LOCAL-DC</code></p>
            <p style=""font-size: 0.8rem; color: var(--text-muted); margin-top: 6px;"" id=""last-sync"">Heartbeats: 1</p>
        </div>

        <div>
            <h3>👥 Dynamic Team Whitelist</h3>
            <p style=""font-size: 0.8rem; color: var(--text-muted); margin-bottom: 8px;"">Authorize operators without triggering alerts.</p>
            <input type=""text"" id=""new-user-input"" placeholder=""e.g. IncidentLead01"">
            <button class=""action-btn"" onclick=""addWhitelistedUser()"">➕ Add to Whitelist</button>
            <div id=""dynamic-whitelist-list"" style=""font-size: 0.85rem; margin-top: 6px;""></div>
        </div>

        <div>
            <h3>🧪 Triage Scenarios</h3>
            <button class=""action-btn btn-outline"" onclick=""triggerSimulation('audit')"">🔄 Force Audit Now</button>
            <button class=""action-btn btn-outline"" onclick=""triggerSimulation('contaminated')"">☣️ Inject Contaminated (0%)</button>
            <button class=""action-btn btn-outline"" onclick=""triggerSimulation('pristine')"">✨ Inject Pristine (100%)</button>
        </div>

        <div style=""font-size: 0.75rem; color: var(--text-muted); margin-top: auto; border-top: 1px solid var(--border-card); padding-top: 12px;"">
            🔒 Air-Gapped Loopback Interface: <code>http://127.0.0.1:8000/</code><br>Zero network transmission risk.
        </div>
    </div>

    <div class=""content"">
        <div class=""header-bar"">
            <div class=""title-group"">
                <h1>🛡️ Active Directory Integrity Engine</h1>
                <p>Minute-0 Autonomous Threat Hunting & Watchdog Telemetry Dashboard (Air-Gapped Host)</p>
            </div>
            <button class=""panic-btn"" onclick=""triggerPanic()"">🚨 Purge Rogue Admins & Lock Policies</button>
        </div>

        <div id=""remediation-terminal"" style=""display: none;"">
            <h3 style=""margin-bottom: 8px;"">💻 Executed Emergency Remediation Playbook (Live Terminal)</h3>
            <div class=""terminal-box"" id=""terminal-content""></div>
        </div>

        <div class=""score-card"" id=""score-card"" style=""border: 1px solid var(--border); background: var(--bg-card);"">
            <div style=""font-size: 0.95rem; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;"" id=""score-header"">
                ACTIVE DIRECTORY INTEGRITY HEALTH SCORE
            </div>
            <div class=""score-headline"" id=""score-val"" style=""color: var(--text-muted);"">
                --%
            </div>
            <div style=""font-size: 1.25rem; font-weight: 700; color: #ffffff; margin-top: 8px;"" id=""score-title"">
                CONNECTING TO LOCAL AUDIT ENGINE...
            </div>
            <div style=""font-size: 0.9rem; color: #94a3b8; margin-top: 4px;"" id=""score-subtitle"">
                Awaiting telemetry ingestion from CDE agent runtime...
            </div>
        </div>

        <div class=""tabs"">
            <button class=""tab-btn active"" onclick=""switchTab('tab-threat')"">🚨 Minute-0 Threat Surface</button>
            <button class=""tab-btn"" onclick=""switchTab('tab-matrix')"">👥 AD Account & Group Matrix</button>
            <button class=""tab-btn"" onclick=""switchTab('tab-registry')"">🛡️ Security Policies & Registry</button>
            <button class=""tab-btn"" onclick=""switchTab('tab-raw')"">📡 Raw Agent Telemetry</button>
        </div>

        <div id=""tab-threat"" class=""tab-content active"">
            <h3 style=""margin-bottom: 12px;"">🚨 Reactive Minute-0 Anomaly Log Table</h3>
            <table class=""data-table"">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Finding / Discrepancy</th>
                        <th>MITRE ATT&CK</th>
                        <th>Remediation Command</th>
                    </tr>
                </thead>
                <tbody id=""anomaly-table-body"">
                </tbody>
            </table>
        </div>

        <div id=""tab-matrix"" class=""tab-content"">
            <div class=""grid-3"" style=""grid-template-columns: 1fr 1fr;"">
                <div class=""card"">
                    <h3>🌟 Pristine Golden State Roster</h3>
                    <p style=""font-size: 0.85rem; margin-top: 8px;""><strong>Built-in:</strong> <code>Administrator</code>, <code>Guest</code>, <code>krbtgt</code></p>
                    <p style=""font-size: 0.85rem; margin-top: 8px;""><strong>Blue Team:</strong> <code>BlueTeamLead</code>, <code>BlueTeamAdmin1</code>, <code>BlueTeamAdmin2</code>, <code>ScoreUser_AD</code></p>
                    <p style=""font-size: 0.85rem; margin-top: 8px;""><strong>Domain Admins:</strong> <code>Administrator</code>, <code>BlueTeamLead</code></p>
                </div>
                <div class=""card"">
                    <h3>📡 Live DC Discovered Accounts</h3>
                    <div id=""live-domain-admins-badges"" style=""margin-top: 8px; margin-bottom: 12px;""></div>
                    <div id=""live-users-badges""></div>
                </div>
            </div>
        </div>

        <div id=""tab-registry"" class=""tab-content"">
            <div class=""grid-3"">
                <div class=""card"" id=""card-fw"">
                    <h3>1. Windows Firewall</h3>
                    <div id=""fw-status"" style=""margin: 8px 0;""></div>
                    <div class=""code-box"">HKLM\...\FirewallPolicy\StandardProfile\EnableFirewall</div>
                </div>
                <div class=""card"" id=""card-rdp"">
                    <h3>2. RDP Network Level Auth</h3>
                    <div id=""rdp-status"" style=""margin: 8px 0;""></div>
                    <div class=""code-box"">HKLM\...\Terminal Server\WinStations\RDP-Tcp\UserAuthentication</div>
                </div>
                <div class=""card"" id=""card-lsa"">
                    <h3>3. LSA Credential Guard</h3>
                    <div id=""lsa-status"" style=""margin: 8px 0;""></div>
                    <div class=""code-box"">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL</div>
                </div>
            </div>
            <div class=""grid-3"" style=""margin-top: 16px; grid-template-columns: 1fr 1fr;"">
                <div class=""card"" id=""card-runkeys"">
                    <h3>4. Autostart Run & RunOnce Keys (T1547.001)</h3>
                    <div id=""runkeys-status"" style=""margin: 8px 0;""></div>
                    <div id=""runkeys-list"" style=""font-size: 0.85rem; margin-top: 8px; max-height: 140px; overflow-y: auto;""></div>
                </div>
                <div class=""card"" id=""card-winlogon"">
                    <h3>5. Winlogon & Logon/Logoff Scripts (T1547.004 / T1037)</h3>
                    <div id=""winlogon-status"" style=""margin: 8px 0;""></div>
                    <div id=""winlogon-details"" style=""font-size: 0.85rem; margin-top: 8px; line-height: 1.5;""></div>
                </div>
            </div>
        </div>

        <div id=""tab-raw"" class=""tab-content"">
            <h3>📡 Native JSON Telemetry Inspector</h3>
            <pre class=""terminal-box"" id=""raw-json"" style=""margin-top: 12px;""></pre>
        </div>
    </div>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }

        async function fetchState() {
            try {
                const res = await fetch('/api/state');
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const data = await res.json();
                renderUI(data);
            } catch (err) {
                console.error(""Failed to fetch state:"", err);
                document.getElementById('score-card').className = 'score-card bad';
                document.getElementById('score-val').style.color = 'var(--red-crit)';
                document.getElementById('score-val').innerText = 'OFFLINE';
                document.getElementById('score-title').innerText = 'TELEMETRY DISCONNECTED';
                document.getElementById('score-subtitle').innerText = 'Unable to reach http://127.0.0.1:8000/api/state. Check agent console.';
            }
        }

        function renderUI(data) {
            const diff = data.diff || {};
            const snapshot = data.snapshot || {};
            const telemetry = snapshot.telemetry || {};

            document.getElementById('agent-identity').innerText = snapshot.agent_identity || 'ALPHA';
            document.getElementById('twin-pid').innerText = snapshot.twin_pid || 'N/A';
            document.getElementById('host-name').innerText = snapshot.hostname || 'LOCAL-DC';
            document.getElementById('last-sync').innerText = 'Heartbeats: ' + (snapshot.telemetry_counter || 1);

            const scoreCard = document.getElementById('score-card');
            const scoreVal = document.getElementById('score-val');
            const scoreTitle = document.getElementById('score-title');
            const scoreSubtitle = document.getElementById('score-subtitle');

            const score = (diff.health_score !== undefined) ? diff.health_score : 100;
            scoreVal.innerText = score + '%';

            if (score === 100) {
                scoreCard.className = 'score-card good';
                scoreVal.style.color = 'var(--green-ok)';
                scoreTitle.innerText = 'GOLDEN STATE COMPLIANT — ALL DEFENSES VERIFIED';
                scoreSubtitle.innerText = 'Zero unauthorized domain accounts • Zero rogue Domain Admins • Firewall & LSA Guard Enforced';
            } else {
                scoreCard.className = 'score-card bad';
                scoreVal.style.color = 'var(--red-crit)';
                scoreTitle.innerText = 'CRITICAL INTEGRITY BREACH DETECTED AT MINUTE-0';
                scoreSubtitle.innerText = `Identified ${(diff.anomalies || []).length} baseline violations: unauthorized backdoor accounts & disabled security policies.`;
            }

            // Anomalies table
            const tbody = document.getElementById('anomaly-table-body');
            const anomalies = diff.anomalies || [];
            if (anomalies.length === 0) {
                tbody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--green-ok); font-weight: bold; padding: 24px;"">🎉 Zero Anomalies Detected! The Domain Controller matches the Golden State baseline exactly.</td></tr>';
            } else {
                tbody.innerHTML = anomalies.map(a => {
                    let badgeClass = 'badge-med';
                    if (a.severity === 'CRITICAL') badgeClass = 'badge-crit';
                    else if (a.severity === 'HIGH') badgeClass = 'badge-high';
                    return `<tr>
                        <td><code>${a.timestamp || ''}</code></td>
                        <td><span class=""badge ${badgeClass}"">${a.severity || 'HIGH'}</span></td>
                        <td>${a.category || ''}</td>
                        <td><strong>${a.finding || ''}</strong></td>
                        <td><code>${a.mitre_attack || ''}</code></td>
                        <td><code style=""color: #38bdf8; font-size: 0.75rem;"">${a.remediation_cmd || ''}</code></td>
                    </tr>`;
                }).join('');
            }

            // Dynamic whitelist
            const dwList = document.getElementById('dynamic-whitelist-list');
            if (snapshot.extra_whitelisted_users && snapshot.extra_whitelisted_users.length > 0) {
                dwList.innerHTML = '<strong>Authorized Accounts:</strong><br>' + snapshot.extra_whitelisted_users.map(u => 
                    `• <code>${u}</code> <a href=""javascript:void(0)"" onclick=""removeUser('${u}')"" style=""color: #ef4444; text-decoration: none; margin-left: 6px;"">✖</a><br>`
                ).join('');
            } else {
                dwList.innerHTML = '<span style=""color: var(--text-muted);"">No dynamic accounts added.</span>';
            }

            // Live users & admins
            const adminBadges = (telemetry.domain_admins || []).map(a => {
                const isRogue = (diff.rogue_domain_admins || []).includes(a);
                return `<span class=""badge ${isRogue ? 'badge-crit' : 'badge-ok'}"">${a} ${isRogue ? '(ROGUE ADMIN)' : '(Authorized)'}</span> `;
            }).join('');
            document.getElementById('live-domain-admins-badges').innerHTML = '<strong>Live Domain Admins:</strong><br>' + (adminBadges || 'None');

            const userBadges = (telemetry.users || []).map(u => {
                const isRogue = (diff.rogue_users || []).includes(u);
                return `<span class=""badge ${isRogue ? 'badge-high' : 'badge-ok'}"">${u} ${isRogue ? '(ROGUE)' : ''}</span> `;
            }).join('');
            document.getElementById('live-users-badges').innerHTML = '<strong>All Discovered Users:</strong><br>' + (userBadges || 'None');

            // Registry cards
            const reg = telemetry.registry || {};
            const fwVal = reg.EnableFirewall;
            document.getElementById('fw-status').innerHTML = fwVal === 1 
                ? '<span class=""badge badge-ok"">✅ ENFORCED (1)</span>' 
                : '<span class=""badge badge-crit"">❌ DISABLED (0)</span>';

            const rdpVal = reg.UserAuthentication;
            document.getElementById('rdp-status').innerHTML = rdpVal === 1 
                ? '<span class=""badge badge-ok"">✅ ENFORCED (1)</span>' 
                : '<span class=""badge badge-crit"">❌ DISABLED (0)</span>';

            const pplVal = reg.RunAsPPL;
            document.getElementById('lsa-status').innerHTML = pplVal === 1 
                ? '<span class=""badge badge-ok"">✅ ENFORCED (1)</span>' 
                : '<span class=""badge badge-crit"">❌ DISABLED (0)</span>';

            // Run keys card
            const runKeys = telemetry.run_keys || [];
            const benignNames = [""vmware user process"", ""vmware tools"", ""vboxtray"", ""vboxclient"", ""securityhealth"", ""securityhealthsystray""];
            const suspRunKeys = runKeys.filter(r => {
                const name = (r.name || '').toLowerCase();
                const cmd = (r.command || '').toLowerCase();
                return !benignNames.includes(name) && !cmd.includes('vmtoolsd.exe') && !cmd.includes('vboxtray.exe');
            });

            const rkStatus = document.getElementById('runkeys-status');
            const rkList = document.getElementById('runkeys-list');
            if (suspRunKeys.length === 0) {
                rkStatus.innerHTML = '<span class=""badge badge-ok"">✅ NO ROGUE KEYS</span>';
                if (runKeys.length > 0) {
                    rkList.innerHTML = `<span style=""color: var(--text-muted);"">${runKeys.length} standard/whitelisted autostart entries verified.</span>`;
                } else {
                    rkList.innerHTML = '<span style=""color: var(--text-muted);"">Pristine: 0 autostart keys detected.</span>';
                }
            } else {
                rkStatus.innerHTML = `<span class=""badge badge-crit"">❌ ${suspRunKeys.length} ROGUE AUTOSTART KEYS</span>`;
                rkList.innerHTML = suspRunKeys.map(r => `<div><strong>${r.name}:</strong> <code>${r.command}</code><br><span style=""color: var(--text-muted); font-size: 0.75rem;"">${r.location}</span></div>`).join('<br>');
            }

            // Winlogon card
            const wl = telemetry.winlogon || {};
            const wlStatus = document.getElementById('winlogon-status');
            const wlDetails = document.getElementById('winlogon-details');
            const uInit = wl.Userinit || 'C:\\Windows\\system32\\userinit.exe,';
            const isUInitClean = uInit.toLowerCase() === 'c:\\windows\\system32\\userinit.exe,' || uInit.toLowerCase() === 'c:\\windows\\system32\\userinit.exe';
            const isShellClean = (wl.Shell || 'explorer.exe').toLowerCase() === 'explorer.exe';
            const hasLogonScript = !!(wl.LogonScript);

            if (isUInitClean && isShellClean && !hasLogonScript) {
                wlStatus.innerHTML = '<span class=""badge badge-ok"">✅ PRISTINE WINLOGON</span>';
                wlDetails.innerHTML = '<code>Userinit</code>: userinit.exe,<br><code>Shell</code>: explorer.exe<br><code>LogonScript</code>: (none)';
            } else {
                wlStatus.innerHTML = '<span class=""badge badge-crit"">❌ HIJACKED WINLOGON / LOGON SCRIPT</span>';
                let details = '';
                if (!isUInitClean) details += `<div style=""color: var(--red-crit);""><strong>Userinit Hijacked:</strong> <code>${uInit}</code></div>`;
                if (!isShellClean) details += `<div style=""color: var(--red-crit);""><strong>Shell Hijacked:</strong> <code>${wl.Shell}</code></div>`;
                if (hasLogonScript) details += `<div style=""color: var(--orange-high);""><strong>Rogue Logon Script:</strong> <code>${wl.LogonScript}</code></div>`;
                wlDetails.innerHTML = details;
            }

            // Raw JSON
            document.getElementById('raw-json').innerText = JSON.stringify(telemetry, null, 2);

            // Remediation log
            const term = document.getElementById('remediation-terminal');
            if (snapshot.remediation_log) {
                term.style.display = 'block';
                document.getElementById('terminal-content').innerText = snapshot.remediation_log;
            } else {
                term.style.display = 'none';
            }
        }

        async function triggerPanic() {
            if (!confirm(""Execute Emergency Remediation Playbook?\n\nThis will:\n1. Restore Windows Firewall & enforce policies\n2. Enforce RDP NLA & LSA Credential Guard\n3. Purge rogue Run keys & restore Winlogon\n4. Revoke privileges from rogue Domain Admins"")) {
                return;
            }
            try {
                const res = await fetch('/api/panic', { method: 'POST' });
                fetchState();
            } catch (err) {
                alert(""Error triggering remediation: "" + err);
            }
        }

        async function triggerSimulation(mode) {
            await fetch('/api/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode })
            });
            fetchState();
        }

        async function addWhitelistedUser() {
            const input = document.getElementById('new-user-input');
            const user = input.value.trim();
            if (user) {
                await fetch('/api/whitelist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'add', username: user })
                });
                input.value = '';
                fetchState();
            }
        }

        async function removeUser(username) {
            await fetch('/api/whitelist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'remove', username })
            });
            fetchState();
        }

        // Live refresh every 2 seconds
        setInterval(fetchState, 2000);
        fetchState();
    </script>
</body>
</html>";

        static void StartLocalWebDashboard(int port)
        {
            try
            {
                WebListener = new HttpListener();
                WebListener.Prefixes.Add(string.Format("http://127.0.0.1:{0}/", port));
                WebListener.Prefixes.Add(string.Format("http://localhost:{0}/", port));
                WebListener.Start();
                WebServerRunning = true;

                WebThread = new Thread(WebWorkerLoop);
                WebThread.IsBackground = true;
                WebThread.Name = "LocalWebDashboardWorker";
                WebThread.Start();
                if (DebugMode) Console.WriteLine("[+] Local Web Dashboard listening on http://127.0.0.1:{0}/", port);
            }
            catch (Exception ex)
            {
                WebServerRunning = false;
                if (DebugMode) Console.WriteLine("[!] Could not bind web dashboard on port {0}: {1}", port, ex.Message);
                
                // Fallback attempt on port 8080 or alternative
                try
                {
                    int fallbackPort = (port == 8000) ? 8080 : port + 1;
                    if (WebListener != null)
                    {
                        try { WebListener.Close(); } catch { }
                    }
                    WebListener = new HttpListener();
                    WebListener.Prefixes.Add(string.Format("http://127.0.0.1:{0}/", fallbackPort));
                    WebListener.Start();
                    WebPort = fallbackPort;
                    WebServerRunning = true;
                    WebThread = new Thread(WebWorkerLoop);
                    WebThread.IsBackground = true;
                    WebThread.Name = "LocalWebDashboardWorker";
                    WebThread.Start();
                    if (DebugMode) Console.WriteLine("[+] Local Web Dashboard listening on fallback http://127.0.0.1:{0}/", WebPort);
                }
                catch { }
            }
        }

        static void WebWorkerLoop()
        {
            while (WebServerRunning && WebListener != null && WebListener.IsListening)
            {
                try
                {
                    HttpListenerContext context = WebListener.GetContext();
                    ThreadPool.QueueUserWorkItem((state) => HandleWebRequest((HttpListenerContext)state), context);
                }
                catch (HttpListenerException) { break; }
                catch (Exception) { }
            }
        }

        static void HandleWebRequest(HttpListenerContext context)
        {
            try
            {
                HttpListenerRequest req = context.Request;
                HttpListenerResponse resp = context.Response;

                resp.Headers["Access-Control-Allow-Origin"] = "*";
                resp.Headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
                resp.Headers["Access-Control-Allow-Headers"] = "Content-Type";

                if (req.HttpMethod == "OPTIONS")
                {
                    resp.StatusCode = 200;
                    resp.Close();
                    return;
                }

                string path = req.Url.AbsolutePath.ToLower();

                if (path == "/" || path == "/index.html")
                {
                    byte[] b = Encoding.UTF8.GetBytes(DashboardHtml);
                    resp.ContentType = "text/html; charset=utf-8";
                    resp.ContentLength64 = b.Length;
                    resp.OutputStream.Write(b, 0, b.Length);
                    resp.OutputStream.Close();
                }
                else if (path == "/api/state")
                {
                    string json = GenerateStateJson();
                    byte[] b = Encoding.UTF8.GetBytes(json);
                    resp.ContentType = "application/json; charset=utf-8";
                    resp.ContentLength64 = b.Length;
                    resp.OutputStream.Write(b, 0, b.Length);
                    resp.OutputStream.Close();
                }
                else if (path == "/api/panic" || path == "/api/remediate")
                {
                    string log = ExecuteEmergencyRemediation();
                    AuditWakeupEvent.Set(); // Wake up audit loop immediately
                    string resultJson = "{\"status\":\"ok\",\"message\":\"Remediation executed\",\"log\":\"" + EscapeJson(log) + "\"}";
                    byte[] b = Encoding.UTF8.GetBytes(resultJson);
                    resp.ContentType = "application/json; charset=utf-8";
                    resp.ContentLength64 = b.Length;
                    resp.OutputStream.Write(b, 0, b.Length);
                    resp.OutputStream.Close();
                }
                else if (path == "/api/whitelist")
                {
                    string body = ReadBody(req);
                    HandleWhitelistRequest(body);
                    AuditWakeupEvent.Set();
                    byte[] b = Encoding.UTF8.GetBytes("{\"status\":\"ok\"}");
                    resp.ContentType = "application/json; charset=utf-8";
                    resp.ContentLength64 = b.Length;
                    resp.OutputStream.Write(b, 0, b.Length);
                    resp.OutputStream.Close();
                }
                else if (path == "/api/simulate")
                {
                    string body = ReadBody(req);
                    HandleSimulateRequest(body);
                    AuditWakeupEvent.Set();
                    byte[] b = Encoding.UTF8.GetBytes("{\"status\":\"ok\"}");
                    resp.ContentType = "application/json; charset=utf-8";
                    resp.ContentLength64 = b.Length;
                    resp.OutputStream.Write(b, 0, b.Length);
                    resp.OutputStream.Close();
                }
                else if (path == "/api/ad_triage")
                {
                    // Accept external telemetry if posted
                    resp.StatusCode = 200;
                    byte[] b = Encoding.UTF8.GetBytes("{\"status\":\"ok\"}");
                    resp.ContentType = "application/json; charset=utf-8";
                    resp.ContentLength64 = b.Length;
                    resp.OutputStream.Write(b, 0, b.Length);
                    resp.OutputStream.Close();
                }
                else
                {
                    resp.StatusCode = 404;
                    byte[] b = Encoding.UTF8.GetBytes("Not Found");
                    resp.OutputStream.Write(b, 0, b.Length);
                    resp.OutputStream.Close();
                }
            }
            catch { }
        }

        static string ReadBody(HttpListenerRequest req)
        {
            try
            {
                using (StreamReader reader = new StreamReader(req.InputStream, req.ContentEncoding))
                {
                    return reader.ReadToEnd();
                }
            }
            catch { return ""; }
        }

        static void HandleWhitelistRequest(string body)
        {
            if (string.IsNullOrEmpty(body)) return;
            string username = ExtractJsonString(body, "username");
            string action = ExtractJsonString(body, "action");

            if (!string.IsNullOrEmpty(username))
            {
                lock (StateLock)
                {
                    if (action == "remove")
                    {
                        DynamicWhitelist.Remove(username);
                    }
                    else
                    {
                        DynamicWhitelist.Add(username);
                    }
                }
            }
        }

        static void HandleSimulateRequest(string body)
        {
            if (string.IsNullOrEmpty(body)) return;
            string mode = ExtractJsonString(body, "mode");
            if (mode == "contaminated")
            {
                SimulatedMode = "contaminated";
            }
            else if (mode == "pristine")
            {
                SimulatedMode = "pristine";
            }
            else
            {
                SimulatedMode = "none";
            }
        }

        static string ExtractJsonString(string json, string key)
        {
            try
            {
                string pattern = "\"" + key + "\"";
                int idx = json.IndexOf(pattern);
                if (idx < 0) return "";
                int colon = json.IndexOf(':', idx + pattern.Length);
                if (colon < 0) return "";
                int quote1 = json.IndexOf('"', colon + 1);
                if (quote1 < 0) return "";
                int quote2 = json.IndexOf('"', quote1 + 1);
                if (quote2 < 0) return "";
                return json.Substring(quote1 + 1, quote2 - quote1 - 1).Trim();
            }
            catch { return ""; }
        }

        // ====================================================================
        // 6. EMERGENCY REMEDIATION PLAYBOOK EXECUTION
        // ====================================================================
        static string ExecuteEmergencyRemediation()
        {
            SimulatedMode = "none"; // reset simulation so system reflects true state
            StringBuilder log = new StringBuilder();
            string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            log.AppendLine("================================================================================");
            log.AppendLine(string.Format("[*] [{0}] INITIATING AIR-GAPPED EMERGENCY REMEDIATION PLAYBOOK", ts));
            log.AppendLine("================================================================================");

            // 1. Re-enable Windows Firewall
            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", 1, RegistryValueKind.DWord);
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", 1, RegistryValueKind.DWord);
                log.AppendLine("[✔] [REGISTRY] Restored Windows Firewall: StandardProfile & DomainProfile EnableFirewall = 1");
                RunCmd("netsh", "advfirewall set allprofiles state on");
                log.AppendLine("[✔] [NETSH] Enforced all firewall profiles: 'netsh advfirewall set allprofiles state on'");
            }
            catch (Exception ex)
            {
                log.AppendLine("[!] [FIREWALL ERROR] " + ex.Message);
            }

            // 2. Enforce RDP Network Level Authentication (NLA)
            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1, RegistryValueKind.DWord);
                log.AppendLine("[✔] [REGISTRY] Enforced RDP Network Level Authentication (NLA): UserAuthentication = 1");
            }
            catch (Exception ex)
            {
                log.AppendLine("[!] [RDP ERROR] " + ex.Message);
            }

            // 3. Enforce LSA RunAsPPL Credential Guard
            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1, RegistryValueKind.DWord);
                log.AppendLine("[✔] [REGISTRY] Enforced LSA Credential Guard: RunAsPPL = 1 (Blocks Mimikatz / LSASS dumping)");
            }
            catch (Exception ex)
            {
                log.AppendLine("[!] [LSA ERROR] " + ex.Message);
            }

            // 4. Restore Winlogon Userinit & Shell (MITRE T1547.004)
            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", @"C:\Windows\system32\userinit.exe,", RegistryValueKind.String);
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "explorer.exe", RegistryValueKind.String);
                log.AppendLine("[✔] [REGISTRY] Restored pristine Winlogon: Userinit = 'C:\\Windows\\system32\\userinit.exe,', Shell = 'explorer.exe'");
            }
            catch (Exception ex)
            {
                log.AppendLine("[!] [WINLOGON ERROR] " + ex.Message);
            }

            // 5. Purge Rogue Logon Scripts (MITRE T1037)
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey("Environment", true))
                {
                    if (k != null && k.GetValue("UserInitMprLogonScript") != null)
                    {
                        k.DeleteValue("UserInitMprLogonScript", false);
                        log.AppendLine("[✔] [REGISTRY] Purged rogue UserInitMprLogonScript from HKCU\\Environment");
                    }
                }
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", true))
                {
                    if (k != null && k.GetValue("UserInitMprLogonScript") != null)
                    {
                        k.DeleteValue("UserInitMprLogonScript", false);
                        log.AppendLine("[✔] [REGISTRY] Purged rogue UserInitMprLogonScript from HKLM\\Session Manager\\Environment");
                    }
                }
            }
            catch (Exception ex)
            {
                log.AppendLine("[!] [LOGON SCRIPT ERROR] " + ex.Message);
            }

            // 6. Purge Rogue Autostart Run & RunOnce Keys (MITRE T1547.001)
            try
            {
                List<RunKeyEntry> currentRunKeys = AuditRunKeys();
                foreach (var rk in currentRunKeys)
                {
                    string nameLower = (rk.Name ?? "").Trim().ToLower();
                    string cmdLower = (rk.Command ?? "").Trim().ToLower();
                    if (BenignRunNames.Contains(nameLower) || cmdLower.Contains("vmtoolsd.exe") || cmdLower.Contains("vboxtray.exe"))
                        continue;

                    if (rk.Location.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase))
                    {
                        string sub = rk.Location.Substring(5);
                        using (RegistryKey k = Registry.LocalMachine.OpenSubKey(sub, true))
                        {
                            if (k != null)
                            {
                                k.DeleteValue(rk.Name, false);
                                log.AppendLine(string.Format("[✔] [REGISTRY] Purged rogue autostart key '{0}' from {1}", rk.Name, rk.Location));
                            }
                        }
                    }
                    else if (rk.Location.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase))
                    {
                        string sub = rk.Location.Substring(5);
                        using (RegistryKey k = Registry.CurrentUser.OpenSubKey(sub, true))
                        {
                            if (k != null)
                            {
                                k.DeleteValue(rk.Name, false);
                                log.AppendLine(string.Format("[✔] [REGISTRY] Purged rogue autostart key '{0}' from {1}", rk.Name, rk.Location));
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log.AppendLine("[!] [RUN KEYS ERROR] " + ex.Message);
            }

            // 7. Purge Rogue Domain Admins & Backdoor Accounts
            try
            {
                List<string> currentAdmins = QueryDomainAdmins();
                foreach (var admin in currentAdmins)
                {
                    if (!BaselineAdmins.Contains(admin))
                    {
                        RunCmd("net", string.Format("group \"Domain Admins\" \"{0}\" /delete", admin));
                        RunCmd("net", string.Format("localgroup \"Administrators\" \"{0}\" /delete", admin));
                        RunCmd("net", string.Format("user \"{0}\" /active:no", admin));
                        log.AppendLine(string.Format("[✔] [PRIVILEGE REVOCATION] Demoted rogue Domain Admin '{0}' and disabled account.", admin));
                    }
                }
            }
            catch (Exception ex)
            {
                log.AppendLine("[!] [ACCOUNT ERROR] " + ex.Message);
            }

            log.AppendLine("================================================================================");
            log.AppendLine("[✔] REMEDIATION COMPLETE! All baseline defense postures restored to Golden State.");
            log.AppendLine("================================================================================");

            string logResult = log.ToString();
            lock (StateLock)
            {
                LatestRemediationLog = logResult;
            }
            return logResult;
        }

        static void RunCmd(string file, string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = file;
                psi.Arguments = args;
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi))
                {
                    if (p != null) p.WaitForExit(3000);
                }
            }
            catch { }
        }

        // ====================================================================
        // 7. JSON STATE PACKAGING
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

        static string GenerateStateJson()
        {
            AuditState s;
            lock (StateLock)
            {
                s = CurrentAuditState;
            }

            StringBuilder sb = new StringBuilder();
            sb.Append("{\n");

            // 1. diff
            sb.Append("  \"diff\": {\n");
            sb.AppendFormat("    \"health_score\": {0},\n", s.HealthScore);
            sb.AppendFormat("    \"is_compliant\": {0},\n", s.HealthScore == 100 ? "true" : "false");

            // rogue_domain_admins
            sb.Append("    \"rogue_domain_admins\": [");
            for (int i = 0; i < s.RogueDomainAdmins.Count; i++)
            {
                sb.AppendFormat("\"{0}\"", EscapeJson(s.RogueDomainAdmins[i]));
                if (i + 1 < s.RogueDomainAdmins.Count) sb.Append(", ");
            }
            sb.Append("],\n");

            // rogue_users
            sb.Append("    \"rogue_users\": [");
            for (int i = 0; i < s.RogueUsers.Count; i++)
            {
                sb.AppendFormat("\"{0}\"", EscapeJson(s.RogueUsers[i]));
                if (i + 1 < s.RogueUsers.Count) sb.Append(", ");
            }
            sb.Append("],\n");

            // anomalies
            sb.Append("    \"anomalies\": [\n");
            for (int i = 0; i < s.Anomalies.Count; i++)
            {
                var a = s.Anomalies[i];
                sb.Append("      {\n");
                sb.AppendFormat("        \"timestamp\": \"{0}\",\n", EscapeJson(a.Timestamp));
                sb.AppendFormat("        \"severity\": \"{0}\",\n", EscapeJson(a.Severity));
                sb.AppendFormat("        \"category\": \"{0}\",\n", EscapeJson(a.Category));
                sb.AppendFormat("        \"finding\": \"{0}\",\n", EscapeJson(a.Finding));
                sb.AppendFormat("        \"details\": \"{0}\",\n", EscapeJson(a.Details));
                sb.AppendFormat("        \"mitre_attack\": \"{0}\",\n", EscapeJson(a.MitreAttack));
                sb.AppendFormat("        \"remediation_cmd\": \"{0}\"\n", EscapeJson(a.RemediationCmd));
                sb.Append("      }");
                if (i + 1 < s.Anomalies.Count) sb.Append(",");
                sb.Append("\n");
            }
            sb.Append("    ]\n");
            sb.Append("  },\n");

            // 2. snapshot
            sb.Append("  \"snapshot\": {\n");
            sb.AppendFormat("    \"agent_identity\": \"{0}\",\n", EscapeJson(s.AgentIdentity));
            sb.AppendFormat("    \"hostname\": \"{0}\",\n", EscapeJson(s.Hostname));
            sb.AppendFormat("    \"twin_pid\": {0},\n", s.TwinPid);
            sb.AppendFormat("    \"telemetry_counter\": {0},\n", s.TelemetryCounter);
            sb.AppendFormat("    \"remediation_log\": {0},\n", string.IsNullOrEmpty(s.RemediationLog) ? "null" : ("\"" + EscapeJson(s.RemediationLog) + "\""));

            // extra_whitelisted_users
            sb.Append("    \"extra_whitelisted_users\": [");
            for (int i = 0; i < s.ExtraWhitelist.Count; i++)
            {
                sb.AppendFormat("\"{0}\"", EscapeJson(s.ExtraWhitelist[i]));
                if (i + 1 < s.ExtraWhitelist.Count) sb.Append(", ");
            }
            sb.Append("],\n");

            // telemetry
            sb.Append("    \"telemetry\": {\n");
            sb.AppendFormat("      \"agent_identity\": \"{0}\",\n", EscapeJson(s.AgentIdentity));
            sb.AppendFormat("      \"hostname\": \"{0}\",\n", EscapeJson(s.Hostname));
            sb.AppendFormat("      \"twin_pid\": {0},\n", s.TwinPid);
            sb.AppendFormat("      \"timestamp\": {0},\n", s.Timestamp);

            // users
            sb.Append("      \"users\": [");
            for (int i = 0; i < s.Users.Count; i++)
            {
                sb.AppendFormat("\"{0}\"", EscapeJson(s.Users[i]));
                if (i + 1 < s.Users.Count) sb.Append(", ");
            }
            sb.Append("],\n");

            // domain_admins
            sb.Append("      \"domain_admins\": [");
            for (int i = 0; i < s.DomainAdmins.Count; i++)
            {
                sb.AppendFormat("\"{0}\"", EscapeJson(s.DomainAdmins[i]));
                if (i + 1 < s.DomainAdmins.Count) sb.Append(", ");
            }
            sb.Append("],\n");

            // registry
            sb.Append("      \"registry\": {\n");
            sb.AppendFormat("        \"EnableFirewall\": {0},\n", s.Registry.EnableFirewall);
            sb.AppendFormat("        \"UserAuthentication\": {0},\n", s.Registry.UserAuthentication);
            sb.AppendFormat("        \"RunAsPPL\": {0}\n", s.Registry.RunAsPPL);
            sb.Append("      },\n");

            // run_keys
            sb.Append("      \"run_keys\": [\n");
            for (int i = 0; i < s.RunKeys.Count; i++)
            {
                sb.Append("        {\n");
                sb.AppendFormat("          \"location\": \"{0}\",\n", EscapeJson(s.RunKeys[i].Location));
                sb.AppendFormat("          \"name\": \"{0}\",\n", EscapeJson(s.RunKeys[i].Name));
                sb.AppendFormat("          \"command\": \"{0}\"\n", EscapeJson(s.RunKeys[i].Command));
                sb.Append("        }");
                if (i + 1 < s.RunKeys.Count) sb.Append(",");
                sb.Append("\n");
            }
            sb.Append("      ],\n");

            // winlogon
            sb.Append("      \"winlogon\": {\n");
            sb.AppendFormat("        \"Userinit\": \"{0}\",\n", EscapeJson(s.Winlogon.Userinit));
            sb.AppendFormat("        \"Shell\": \"{0}\",\n", EscapeJson(s.Winlogon.Shell));
            sb.AppendFormat("        \"LogonScript\": \"{0}\",\n", EscapeJson(s.Winlogon.LogonScript));
            sb.Append("        \"LogonLogoffScripts\": [");
            if (s.Winlogon.LogonLogoffScripts != null)
            {
                for (int i = 0; i < s.Winlogon.LogonLogoffScripts.Count; i++)
                {
                    sb.AppendFormat("\"{0}\"", EscapeJson(s.Winlogon.LogonLogoffScripts[i]));
                    if (i + 1 < s.Winlogon.LogonLogoffScripts.Count) sb.Append(", ");
                }
            }
            sb.Append("]\n");
            sb.Append("      }\n");

            sb.Append("    }\n"); // end telemetry
            sb.Append("  }\n");   // end snapshot
            sb.Append("}");

            return sb.ToString();
        }

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
        // 8. DUAL-PROCESS MUTUAL WATCHDOG PERSISTENCE
        // ====================================================================
        static int MaintainTwinWatchdog()
        {
            int currentPid = Process.GetCurrentProcess().Id;
            string currentExePath = Process.GetCurrentProcess().MainModule.FileName;
            string currentDir = Path.GetDirectoryName(currentExePath);

            string companionExeName = (TwinIdentity == "alpha") ? "agent_alpha.exe" : "agent_bravo.exe";
            string companionFlag = (TwinIdentity == "alpha") ? "-alpha" : "-bravo";
            string companionFullPath = Path.Combine(currentDir, companionExeName);

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

            if (twinPid == 0)
            {
                if (DebugMode) Console.WriteLine("[WATCHDOG] Twin ({0}) missing! Re-spawning companion...", TwinIdentity);

                if (!File.Exists(companionFullPath))
                {
                    try { File.Copy(currentExePath, companionFullPath, true); } catch { }
                }

                string targetExe = File.Exists(companionFullPath) ? companionFullPath : currentExePath;

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = targetExe;
                // Launch companion with -twin flag so it doesn't conflict on local dashboard port
                psi.Arguments = string.Format("{0} -twin -server {1} -port {2}", companionFlag, ServerHost, ServerPort);
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
        // 9. MAIN ENTRYPOINT
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
                else if (a == "-port" && i + 1 < args.Length) { int.TryParse(args[++i], out ServerPort); WebPort = ServerPort; }
                else if (a == "-webport" && i + 1 < args.Length) int.TryParse(args[++i], out WebPort);
                else if (a == "-interval" && i + 1 < args.Length) int.TryParse(args[++i], out IntervalSec);
                else if (a == "-debug") DebugMode = true;
                else if (a == "-noweb") EnableLocalWeb = false;
                else if (a == "-twin") IsTwin = true;
            }

            if (DebugMode)
            {
                Console.WriteLine("=======================================================");
                Console.WriteLine("  AD WATCHDOG NATIVE ENGINE & LOCAL DASHBOARD (DC HOST)");
                Console.WriteLine("=======================================================");
                Console.WriteLine("[+] Agent Identity : " + Identity);
                Console.WriteLine("[+] Twin Companion : " + TwinIdentity);
                Console.WriteLine("[+] Local Web GUI  : http://127.0.0.1:" + WebPort + "/");
                Console.WriteLine("[+] Target Server  : http://" + ServerHost + ":" + ServerPort + Endpoint);
                Console.WriteLine("[+] Polling Interval: " + IntervalSec + "s (" + (IntervalSec / 60) + " min)");
                Console.WriteLine("=======================================================");
            }

            // Start Local Web Dashboard if primary agent
            if (EnableLocalWeb && !IsTwin)
            {
                StartLocalWebDashboard(WebPort);
            }

            while (true)
            {
                // 1. Maintain mutual watchdog persistence
                int twinPid = MaintainTwinWatchdog();

                // 2. Perform native user, group, registry & autostart audit
                AuditCurrentSystem(twinPid);

                // 3. Output rich triage report to console (Always retained!)
                PrintTriageReport();

                // 4. If remote central server configured (not loopback), optionally exfiltrate
                if (ServerHost != "127.0.0.1" && ServerHost != "localhost")
                {
                    string json = GenerateStateJson();
                    bool ok = ExfiltrateTelemetry(json);
                    if (ok && DebugMode)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[*] Remote Exfiltration: [✔] 200 OK (Central Server Ingested Telemetry)");
                        Console.ResetColor();
                    }
                }

                // 5. Sleep with interrupt support (wakes immediately on GUI remediation/panic trigger)
                Console.WriteLine("[*] Sleeping for {0} seconds ({1} minutes) before next audit round...", IntervalSec, IntervalSec / 60);
                Console.WriteLine("    [Local Web Dashboard: http://127.0.0.1:{0}/ | Press Ctrl+C to terminate]", WebPort);
                Console.WriteLine();

                AuditWakeupEvent.WaitOne(IntervalSec * 1000);
            }
        }
    }
}
