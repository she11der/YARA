rule REVERSINGLABS_Win32_Ransomware_Matsnu : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Matsnu ransomware."
		author = "ReversingLabs"
		id = "2f0bddd5-bd48-5d38-84f4-2dbccbe04a46"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Matsnu.yara#L1-L116"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "76ef1b4a292f27ccd904e80f0279a7a327f7399a21f2266ef3ea959e5339ffac"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Matsnu"
		tc_detection_factor = 5
		importance = 25

	strings:
		$remote_connection = {
            55 89 E5 81 EC ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C6 45 ?? ?? 89 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B 8D 83 ?? ?? ?? ?? 8B 00 6A ?? 50 
            FF 93 ?? ?? ?? ?? 8D B3 ?? ?? ?? ?? 8B 36 8D 7D ?? 57 56 FF 93 ?? ?? ?? ?? 85 C0 74 
            ?? 57 8D BB ?? ?? ?? ?? 89 07 5F EB ?? 8D B3 ?? ?? ?? ?? 8B 36 57 8D BB ?? ?? ?? ?? 
            89 37 5F 68 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? EB ?? 8D BD ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 
            ?? 57 FF 93 ?? ?? ?? ?? 8D B3 ?? ?? ?? ?? 8B 36 8D BD ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 
            57 FF 93 ?? ?? ?? ?? 8D 83 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 50 57 FF 93 ?? ?? ?? ?? 85 
            C0 74 ?? C6 00 ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8D B3 ?? ?? ?? ?? 8D 93 ?? ?? 
            ?? ?? FF 75 ?? 52 51 56 57 FF 93 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 4D ?? 51 57 E8 ?? 
            ?? ?? ?? 85 C0 74 ?? 89 45 ?? 8D 4D ?? 51 50 E8 ?? ?? ?? ?? 85 C0 75 ?? FF 75 ?? FF 
            93 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 89 85 ?? ?? ?? ?? FF 75 ?? FF 93 ?? ?? ?? 
            ?? 8B 45 ?? 8B 75 ?? 89 06 50 FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 83 BD ?? 
            ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            68 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? 8D B3 ?? ?? ?? ?? 8B 36 8D 83 ?? ?? ?? ?? 50 56 FF 
            93 ?? ?? ?? ?? 85 C0 74 ?? 40 57 8D BB ?? ?? ?? ?? 89 07 5F E9 ?? ?? ?? ?? 8D B3 ?? 
            ?? ?? ?? 8B 36 57 8D BB ?? ?? ?? ?? 89 37 5F 68 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? E9 ?? 
            ?? ?? ?? 8D 83 ?? ?? ?? ?? 8B 00 50 FF 93 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 9D ?? ?? 
            ?? ?? C9 C2 
        }
		$crypto_file = {
            55 89 E5 83 EC ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? C6 45 ?? ?? 
            C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 5D ?? E8 
            ?? ?? ?? ?? 5B 8D 83 ?? ?? ?? ?? 8B 00 85 C0 74 ?? 89 45 ?? 8D 83 ?? ?? ?? ?? 8B 00 
            85 C0 74 ?? 8D 7D ?? 8D 75 ?? 8D 4D ?? 51 56 57 FF 75 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 
            89 45 ?? 83 7D ?? ?? 74 ?? FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? EB ?? FF 75 ?? FF 75 ?? 
            FF 93 ?? ?? ?? ?? FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? EB ?? C7 45 ?? ?? ?? ?? ?? 8B 45 
            ?? 8B 5D ?? C9 C2
        }
		$crypt_file = {
            55 89 E5 81 EC ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            5B 8D BD ?? ?? ?? ?? FF 75 ?? 57 FF 93 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D B3 ?? ?? ?? 
            ?? 56 57 FF 93 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 57 FF 93 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 50 FF 93 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 51 6A ?? 6A ?? 68 ?? ?? ?? ?? FF 30 FF 93 ?? 
            ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 4D ?? 8D 85 ?? ?? ?? ?? 6A ?? 
            FF 31 50 FF 36 FF 93 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? 8D B5 ?? ?? ?? ?? 51 6A ?? FF 36 68 ?? ?? ?? ?? FF 30 FF 93 ?? ?? ?? ?? 85 
            C0 0F 84 ?? ?? ?? ?? FF 75 ?? 6A ?? FF 93 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 89 45 
            ?? 6A ?? FF 75 ?? FF 93 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? FF 
            75 ?? FF 93 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 89 45 ?? 8D 7D ?? 8D 75 ?? 8D 55 
            ?? 52 56 57 FF 75 ?? FF 93 ?? ?? ?? ?? 8B 45 ?? 3D ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 
            45 ?? 6A ?? 50 FF 75 ?? FF 75 ?? FF 75 ?? FF 93 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 
            FF 75 ?? FF 93 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? FF 75 
            ?? FF 75 ?? E8 ?? ?? ?? ?? 8D 7D ?? 8D B5 ?? ?? ?? ?? FF 75 ?? 57 FF 75 ?? 6A ?? 6A 
            ?? 6A ?? FF 36 FF 93 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? 
            ?? ?? FF 75 ?? FF 93 ?? ?? ?? ?? 83 F8 ?? 74 ?? 89 45 ?? 8D 45 ?? 6A ?? 50 FF 75 ?? 
            FF 75 ?? FF 75 ?? FF 93 ?? ?? ?? ?? 85 C0 74 ?? 8D 7D ?? 8D 75 ?? 8D 55 ?? 52 56 57 
            FF 75 ?? FF 93 ?? ?? ?? ?? FF 75 ?? FF 93 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D B3 ?? 
            ?? ?? ?? FF 06 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 93 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 50 FF 93 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 6A ?? 50 FF 93 ?? ?? ?? ?? 
            83 7D ?? ?? 74 ?? FF 75 ?? FF 93 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? FF 75 ?? FF 93 ?? ?? 
            ?? ?? 8B 85 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? C9 C2
        }
		$enum_files_1 = {
            89 E5 81 EC ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B E8 ?? 
            ?? ?? ?? 8D 7D ?? 6A ?? FF 75 ?? 57 FF 93 ?? ?? ?? ?? 8D 7D ?? 57 FF 93 ?? ?? ?? ?? 
            83 F8 ?? 74 ?? EB ?? 8D 75 ?? 56 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? C9 C2
        }
		$enum_files_2 = {
            55 89 E5 81 EC ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? 
            66 C7 45 ?? ?? ?? C6 45 ?? ?? 89 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B 83 7D ?? ?? 0F 84 
            ?? ?? ?? ?? FF 75 ?? FF 93 ?? ?? ?? ?? 83 C0 ?? 89 45 ?? 40 50 6A ?? FF 93 ?? ?? ?? 
            ?? 85 C0 0F 84 ?? ?? ?? ?? 89 45 ?? FF 75 ?? FF 75 ?? FF 93 ?? ?? ?? ?? 8D 75 ?? 56 
            FF 75 ?? FF 93 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 57 FF 75 ?? FF 93 ?? ?? ?? ?? 83 F8 ?? 
            0F 84 ?? ?? ?? ?? 89 45 ?? 6A ?? FF 93 ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 55 ?? 8D B5 
            ?? ?? ?? ?? 52 56 FF 93 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 55 ?? 8D B5 ?? ?? ?? ?? 52 
            56 FF 93 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? FF 75 ?? FF 93 ?? ?? ?? ?? 40 89 45 ?? 8D BD 
            ?? ?? ?? ?? 57 FF 93 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 40 50 6A ?? FF 93 ?? ?? ?? ?? 85 
            C0 0F 84 ?? ?? ?? ?? 89 45 ?? FF 75 ?? FF 75 ?? FF 93 ?? ?? ?? ?? 8D 75 ?? 56 FF 75 
            ?? FF 93 ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 56 FF 75 ?? FF 93 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? A9 ?? ?? ?? ?? 74 ?? FF 75 ?? E8 ?? ?? ?? ?? 85 C0 75 ?? FF 75 ?? E8 ?? ?? ?? ?? 
            EB ?? 8D B5 ?? ?? ?? ?? FF 75 ?? 56 FF 75 ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? FF 75 
            ?? FF 93 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 57 FF 75 ?? FF 93 ?? ?? 
            ?? ?? 85 C0 74 ?? E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 83 7D ?? ?? 74 ?? FF 
            75 ?? FF 93 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? FF 75 ?? FF 93 ?? ?? ?? ?? 83 7D ?? ?? 74 
            ?? FF 75 ?? FF 93 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? C9 C2 
        }

	condition:
		uint16(0)==0x5A4D and $enum_files_1 and $enum_files_2 and $crypto_file and $crypt_file and $remote_connection
}
