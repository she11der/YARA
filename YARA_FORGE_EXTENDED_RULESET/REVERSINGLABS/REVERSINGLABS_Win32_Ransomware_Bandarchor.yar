rule REVERSINGLABS_Win32_Ransomware_Bandarchor : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects BandarChor ransomware."
		author = "ReversingLabs"
		id = "c645a081-7ff6-58fc-af8e-55f43f56d0ea"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.BandarChor.yara#L1-L97"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1c0c33ef7de089fc7ed6b364c7693499d1a93f79a48d6f2a5c375e47aea176bc"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "BandarChor"
		tc_detection_factor = 5
		importance = 25

	strings:
		$file_extensions_1 = { 
            55 8B EC B9 ?? ?? ?? ?? 6A ?? 6A ?? 49 75 F9 51 53 89 55 ?? 8B D8 8B 45 ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B 15 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 4D ?? 8B 95 ?? 
            ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 E0 ?? 83 F8 ?? 0F 85 F9 00 00 00 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 55 ?? 8B C3 E8 4F FE FF FF E9 ?? ?? ?? ?? 8D 95
        }
		$file_extensions_2 = { 
            ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? 
            ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? 
            ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8
        }
		$file_extensions_3 = { 
            8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? 
            ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? 
            ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 
            85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 
            8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 
            45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8
        }
		$file_extensions_4 = {  
            0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 
            95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 
            ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 
            84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? 
            ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? 
            E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84
        }
		$file_extensions_5 = {  
            ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 
            ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? 
            ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84
            }
		$parse_server_commands = {
            83 F9 ?? 0F 84 E0 00 00 00 50 53 56 57 89 C3 89 D6 89 CF 31 D2 8A 06 8A 56 ?? 3C ?? 74 25 3C ?? 74 3E 3C ?? 74 51 3C ?? 
            74 5C 3C ?? 74 76 3C ?? 0F 84 84 00 00 00 3C ?? 0F 84 8B 00 00 00 E9 97 00 00 00 83 F9 ?? 89 D8 7F 0A E8 ?? ?? ?? ?? E9 
            91 00 00 00 89 CA E8 ?? ?? ?? ?? E9 85 00 00 00 83 F9 ?? 89 D8 7F 07 E8 ?? ?? ?? ?? EB 77 89 CA E8 ?? ?? ?? ?? EB 6E 89 
            D8 83 C3 ?? E8 ?? ?? ?? ?? 4F 7F F3 EB 5F 55 89 D5 8B 54 2E ?? 89 D8 03 5C 2E ?? 8B 4C 2E ?? 8B 12 E8 62 FF FF FF 4F 7F 
            E8 5D EB 41 55 89 D5 89 D8 03 5C 2E ?? 89 F2 E8 ?? ?? ?? ?? 4F 7F F0 5D EB 2B 89 D8 83 C3 ?? E8 ?? ?? ?? ?? 4F 7F F3 EB 
            1C 89 D8 89 F2 83 C3 ?? E8 ?? ?? ?? ?? 4F 7F F1 EB 0B 5F 5E 5B 58 B0 ?? E9 ?? ?? ?? ?? 5F 5E 5B 58 C3 8B C0 B9 ?? ?? ?? 
            ?? E9 0A FF FF FF C3
        }

	condition:
		uint16(0)==0x5A4D and (($file_extensions_1 and $file_extensions_2 and $file_extensions_3 and $file_extensions_4 and $file_extensions_5) and $parse_server_commands)
}
