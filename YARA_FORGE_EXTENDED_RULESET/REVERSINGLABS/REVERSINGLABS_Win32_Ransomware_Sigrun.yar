rule REVERSINGLABS_Win32_Ransomware_Sigrun : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Sigrun ransomware."
		author = "ReversingLabs"
		id = "fa627192-ed80-5115-a028-014f67f4571d"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Sigrun.yara#L1-L111"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ea29ec64cdfc0c714fe0acdce5878cb1302dd5aa916811121c644948ce275935"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Sigrun"
		tc_detection_factor = 5
		importance = 25

	strings:
		$find_files = {
            55 8B EC 83 E4 ?? 81 EC ?? ?? ?? ?? 83 7D ?? ?? 53 56 57 8B DA C7 44 24 ?? ?? ?? ?? 
            ?? 8B F1 75 ?? 8D 54 24 ?? E8 ?? ?? ?? ?? 8B 7C 24 ?? 89 7C 24 ?? 85 C0 75 ?? 85 FF 
            75 ?? 5F 5E 5B 8B E5 5D C3 C7 44 24 ?? ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 85 C0 75 ?? 
            A1 ?? ?? ?? ?? 89 44 24 ?? A1 ?? ?? ?? ?? 89 44 24 ?? 0F B7 06 66 89 44 24 ?? 83 F8 
            ?? 0F 84 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 56 
            FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 8D 04 46 89 44 24 ?? FF D7 8D 
            44 24 ?? 50 56 FF 15 ?? ?? ?? ?? 8B 4C 24 ?? 33 D2 89 44 24 ?? 66 89 11 83 F8 ?? 75 
            ?? B8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? 
            ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 
            ?? 8D 44 24 ?? 50 56 FF D7 F6 44 24 ?? ?? 74 ?? 83 7C 24 ?? ?? 74 ?? BA ?? ?? ?? ?? 
            8B CE E8 ?? ?? ?? ?? 85 C0 74 ?? 68 ?? ?? ?? ?? 56 FF D7 6A ?? 8B D3 8B CE E8 ?? ?? 
            ?? ?? EB ?? 68 ?? ?? ?? ?? 56 FF D7 6A ?? 8B D3 8B CE E8 ?? ?? ?? ?? EB ?? 53 8D 54 
            24 ?? 8B CE E8 ?? ?? ?? ?? 83 C4 ?? 8B 44 24 ?? 33 C9 66 89 08 8D 44 24 ?? 50 FF 74 
            24 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 5F 5E 
            33 C0 5B 8B E5 5D C3
        }
		$encrypt_files_1 = {
            55 8B EC 83 EC ?? 53 57 68 ?? ?? ?? ?? 8B FA 8B D9 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 6A ?? 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 C7 45 ?? ?? ?? ?? ?? FF 
            15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 5F 33 C0 5B 8B E5 5D C3 
            56 8D 45 ?? 33 F6 50 56 56 57 53 FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 56 8D 45 ?? 
            C7 45 ?? ?? ?? ?? ?? 50 8D 45 ?? 50 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? 8B 45 ?? 68 ?? 
            ?? ?? ?? 50 FF 75 ?? C7 00 ?? ?? ?? ?? 56 6A ?? 56 FF 75 ?? FF 15 ?? ?? ?? ?? 8B F0 
            FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 6A ?? FF 75 ?? FF 15 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? FF 15 ?? ?? ?? ?? 8B C6 5E 5F 5B 8B E5 5D C3
        }
		$encrypt_files_2 = {
            55 8B EC 53 56 57 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8B DA 8B F9 FF 15 ?? ?? 
            ?? ?? 57 8B F0 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 C4 ?? 8B CF E8 ?? ?? ?? ?? 85 
            C0 74 ?? 68 ?? ?? ?? ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B 5D C3 8B CF E8 ?? 
            ?? ?? ?? 85 C0 75 ?? 83 7B ?? ?? 72 ?? 8B 55 ?? 8B CF E8 ?? ?? ?? ?? 85 C0 74 ?? 56 
            57 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 5F 5E B8 ?? ?? ?? ?? 
            5B 5D C3 
        }
		$encrypt_files_3 = {
            55 8B EC 83 EC ?? 56 57 E8 ?? ?? ?? ?? 85 C0 75 ?? 83 C8 ?? 5F 5E 8B E5 5D C3 8D 45 
            ?? 50 8D 45 ?? 50 8D 55 ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F8 8D 4D ?? 8B D7 E8 
            ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 85 C0 74 ?? 8B 4D ?? 85 C9 74 ?? 8B 45 ?? 85 C0 74 ?? 
            C6 04 08 ?? 8B 4D ?? 68 ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 75 
            ?? FF D6 8B CF E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 8D 4D ?? C7 05 ?? ?? ?? ?? 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 75 ?? FF D6 68 ?? ?? ?? ?? 6A ?? 
            57 FF D6 5F 33 C0 5E 8B E5 5D C3
        }
		$enum_resources_1 = {
            55 8B EC 83 E4 ?? 83 EC ?? 53 56 57 8B 3D ?? ?? ?? ?? 8B F1 6A ?? 68 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 6A ?? 89 54 24 ?? 89 74 24 ?? C7 44 24 ?? ?? ?? ?? ?? FF D7 8B 1D ?? ?? 
            ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 85 F6 0F 85 ?? ?? 
            ?? ?? 8D 44 24 ?? 50 6A ?? 6A ?? 6A ?? 6A ?? FF D3 85 C0 0F 85 ?? ?? ?? ?? 8D 44 24 
            ?? C7 44 24 ?? ?? ?? ?? ?? 50 FF 74 24 ?? 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 FF 
            74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 49 ?? 33 DB 39 5C 24 ?? 0F 86 
            ?? ?? ?? ?? 8B 74 24 ?? 83 C6 ?? 83 7E ?? ?? 75 ?? 8B 06 6A ?? 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 6A ?? 89 44 24 ?? FF D7 8B F8 85 FF 74 ?? FF 74 24 ?? 68 ?? ?? ?? ?? 57 FF 
            15 ?? ?? ?? ?? 8B 55 ?? 83 C4 ?? 8B CF 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 
            6A ?? 57 FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? F6 46 ?? ?? 74 ?? FF 75 ?? 8B 54 24 ?? 
            8D 4E ?? E8 ?? ?? ?? ?? 83 C4 ?? 43 83 C6 ?? 3B 5C 24 ?? 72 ?? 8D 44 24 ?? C7 44 24 
            ?? ?? ?? ?? ?? 50 FF 74 24 ?? 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 FF 74 24 ?? FF 
        }
		$enum_resources_2 = {
            15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B 74 24 ?? FF 74 24 ?? FF 
            15 ?? ?? ?? ?? 8D 44 24 ?? 50 56 6A ?? 6A ?? 6A ?? FF D3 8B F0 85 F6 0F 85 ?? ?? ?? 
            ?? 8B 74 24 ?? 8D 44 24 ?? 50 56 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 FF 74 24 ?? 
            C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 9B ?? ?? ?? ?? 
            33 DB 39 5C 24 ?? 0F 86 ?? ?? ?? ?? 83 C6 ?? 90 83 7E ?? ?? 75 ?? 8B 06 6A ?? 68 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 89 44 24 ?? FF D7 8B F8 85 FF 74 ?? FF 74 24 ?? 68 ?? 
            ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 8B 55 ?? 83 C4 ?? 8B CF 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            68 ?? ?? ?? ?? 6A ?? 57 FF 15 ?? ?? ?? ?? F6 46 ?? ?? 74 ?? FF 75 ?? 8B 54 24 ?? 8D 
            4E ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 3D ?? ?? ?? ?? 43 83 C6 ?? 3B 5C 24 ?? 72 ?? 8B 74 
            24 ?? 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 56 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 
            50 FF 74 24 ?? FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? FF 74 24 
            ?? FF 15 ?? ?? ?? ?? 8B F0 68 ?? ?? ?? ?? 6A ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 5F 8B 
            C6 5E 5B 8B E5 5D C3
        }

	condition:
		uint16(0)==0x5A4D and ( all of ($enum_resources_*)) and ($find_files) and ( all of ($encrypt_files_*))
}
