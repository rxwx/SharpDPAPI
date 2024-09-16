using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static SharpDPAPI.Crypto;

namespace SharpDPAPI.Commands
{
    public class Protect : ICommand
    {
        public static string CommandName => "protect";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Encrypt DPAPI blob");

            if (!arguments.ContainsKey("/mkfile"))
            {
                Console.WriteLine("[!] Error: Provide a master key file using /mkfile:<path>");
                return;
            }

            if (!arguments.ContainsKey("/password"))
            {
                Console.WriteLine("[!] Error: Provide a password");
                return;
            }

            if (!arguments.ContainsKey("/input"))
            {
                Console.WriteLine("[!] Error: provide an input file path or base64 using /input:<file>");
                return;
            }

            if (!arguments.ContainsKey("/output"))
            {
                Console.WriteLine("[!] Error: provide an output file path using /output:<file>");
                return;
            }

            byte[] plainBytes;
            byte[] entropy = null;

            string inputFile = arguments["/input"].Trim('"').Trim('\'');
            string outputFile = arguments["/output"].Trim('"').Trim('\'');
            string sid = arguments.ContainsKey("/sid") ? arguments["/sid"] : string.Empty;
            string masterKeyFile = arguments["/mkfile"].Trim('"').Trim('\'');
            string password = arguments["/password"];
            bool isLocalMachine = arguments.ContainsKey("/local");
            string description = arguments.ContainsKey("/description") ? arguments["/description"] : string.Empty;

            if (arguments.ContainsKey("/entropy"))
            {
                entropy = Helpers.StringToByteArray(arguments["/entropy"]);
            }

            if (File.Exists(inputFile))
            {
                plainBytes = File.ReadAllBytes(inputFile);
            }
            else
            {
                plainBytes = Convert.FromBase64String(inputFile);
            }

            Console.WriteLine("[*] Using masterkey: {0}", masterKeyFile);

            string userSID = string.Empty;
            Dictionary<string, string> keyDict;
            KeyValuePair<string, string> keyPair = default;
            
            byte[] masterKeyBytes = null;
            Guid masterKeyGuid = default;

            try
            {
                if (!isLocalMachine)
                {
                    userSID = string.IsNullOrEmpty(sid) ? sid : Dpapi.ExtractSidFromPath(masterKeyFile);
                    keyDict = Triage.TriageUserMasterKeys(null, password: password, target: masterKeyFile, local: true, userSID: userSID);
                    if (keyDict.Count == 1)
                    {
                        keyPair = keyDict.First();
                        masterKeyBytes = Helpers.StringToByteArray(keyPair.Value);
                        masterKeyGuid = new Guid(keyPair.Key);
                    }
                }
                else
                {
                    keyPair = Dpapi.DecryptMasterKeyWithSha(File.ReadAllBytes(masterKeyFile), Helpers.StringToByteArray(password));
                    masterKeyBytes = Helpers.StringToByteArray(keyPair.Value);
                    masterKeyGuid = new Guid(keyPair.Key);
                }
            }
            catch
            {
            }

            if (masterKeyBytes == null || masterKeyGuid == null)
            {
                Console.WriteLine("[!] Failed to decrypt masterkey. Wrong password?");
                return;
            }

            byte[] enc = Dpapi.CreateDPAPIBlob(plainBytes, masterKeyBytes,
                EncryptionAlgorithm.CALG_AES_256,
                HashAlgorithm.CALG_SHA_512,
                masterKeyGuid,
                isLocalMachine: isLocalMachine,
                entropy: entropy,
                description: description
                );

            File.WriteAllBytes(outputFile, enc);
            Console.WriteLine("[+] Done! Wrote {0} bytes to: {1}", enc.Length, outputFile);
            Console.WriteLine("[*] {0}", Convert.ToBase64String(enc));
        }
    }
}