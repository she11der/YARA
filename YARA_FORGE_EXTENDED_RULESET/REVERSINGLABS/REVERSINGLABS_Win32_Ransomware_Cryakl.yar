rule REVERSINGLABS_Win32_Ransomware_Cryakl : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Cryakl ransomware."
		author = "ReversingLabs"
		id = "5c668278-458e-5b13-83c4-63beab5249ed"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Cryakl.yara#L1-L64"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "51d50ab1ce021e2facbca3a35af372186287a8d69b66651c9804234a409d9932"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Cryakl"
		tc_detection_factor = 5
		importance = 25

	strings:
		$enum_and_encrypt_files_1 = {
            8B 85 ?? ?? ?? ?? 50 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? 5A E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? 50 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? 
            ?? ?? 5A E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? 
            ?? ?? 8B 85 ?? ?? ?? ?? 50 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? 5A E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? 5A E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 
            30 64 89 20 8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 80 7C 02 ?? ?? 74 ?? 8D 45 ?? BA ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B 55 ?? 
            E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 
            C0 0F 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? 83 E0 ?? 83 F8 ?? 75 ?? A1 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 8B 10 FF 92 ?? ?? ?? ?? 
            84 C0 0F 84 ?? ?? ?? ?? FF 75 ?? FF B5 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85
        }
		$enum_and_encrypt_files_2 = { 
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 8D 95 ?? 
            ?? ?? ?? 33 C0 E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 
            C6 45 ?? ?? A1 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 8B 10 FF 52 ?? 8B D8 
            4B 85 DB 0F 8C ?? ?? ?? ?? 43 33 F6 8D 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 8D 8D ?? 
            ?? ?? ?? A1 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 8B D6 8B 38 FF 57 ?? 8B 
            85 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 75 ?? C6 45 ?? ?? 
            46 4B 0F 85 ?? ?? ?? ?? 80 7D ?? ?? 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ?? 50 A1 ?? ?? ?? 
            ?? 50 8D 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            8B 0D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 8B 15 ?? ?? ?? 
            ?? 83 C0 ?? 83 D2 ?? 89 05 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 80 ?? ?? 
            ?? ?? 8B 10 FF 92 ?? ?? ?? ?? 84 C0 75 ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 80 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8
        }

	condition:
		uint16(0)==0x5A4D and (( all of ($enum_and_encrypt_files_*)))
}
