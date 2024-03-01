rule REVERSINGLABS_Win64_Ransomware_Whiteblackcrypt : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects WhiteBlackCrypt ransomware."
		author = "ReversingLabs"
		id = "9855c10d-563d-54e0-bc79-945daef947de"
		date = "2021-07-05"
		modified = "2021-07-05"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win64.Ransomware.WhiteBlackCrypt.yara#L1-L91"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "37b95cc3412f2f2d02d19c4c15b529c4f67453cb195627b5bab2f353e7602354"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "WhiteBlackCrypt"
		tc_detection_factor = 5
		importance = 25

	strings:
		$find_files = {
            41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC ?? 4C 8D 3D ?? ?? ?? ?? 45 31 F6 49 89
            CD E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 0F 84 ?? ?? ?? ?? 4C 89 E1 E8 ?? ?? ?? ?? 48 85
            C0 0F 84 ?? ?? ?? ?? 48 8D 68 ?? 4C 89 FA 48 89 E9 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D
            15 ?? ?? ?? ?? 48 89 E9 E8 ?? ?? ?? ?? 85 C0 74 ?? 44 89 F0 48 83 C9 ?? 48 89 EF F2
            AE 4C 89 EF 48 89 CB 48 83 C9 ?? F2 AE 48 F7 D3 48 F7 D1 01 D9 48 63 D9 48 89 D9 E8
            ?? ?? ?? ?? 48 89 D9 4C 89 EA 48 89 C6 48 89 C7 44 89 F0 F3 AA 48 89 F1 E8 ?? ?? ??
            ?? 48 8D 15 ?? ?? ?? ?? 48 89 F1 E8 ?? ?? ?? ?? 48 89 EA 48 89 F1 E8 ?? ?? ?? ?? 48
            89 F1 E8 ?? ?? ?? ?? 48 89 F1 85 C0 74 ?? E8 ?? ?? ?? ?? EB ?? E8 ?? ?? ?? ?? 48 89
            F1 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 89 E1 48 83 C4 ?? 5B 5E 5F 5D 41 5C 41 5D 41 5E
            41 5F E9 ?? ?? ?? ?? 48 83 C4 ?? 5B 5E 5F 5D 41 5C 41 5D 41 5E 41 5F C3
        }
		$encrypt_files = {
            41 55 41 54 55 57 56 53 48 83 EC ?? 48 8D 15 ?? ?? ?? ?? 31 F6 4C 8D 2D ?? ?? ?? ??
            48 89 CD E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 C3 E8 ?? ?? ?? ?? 48 89 C7 49 89 D9 41
            B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 F9 E8 ?? ?? ?? ?? 85 C0 49 89 C4 74 ?? 81 FE ??
            ?? ?? ?? 7F ?? 45 89 E0 48 89 FA 4C 89 E9 E8 ?? ?? ?? ?? 45 31 C0 89 F2 48 89 D9 E8
            ?? ?? ?? ?? 44 01 E6 4D 63 C4 48 89 F9 49 89 D9 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 45 31
            C0 89 F2 48 89 D9 E8 ?? ?? ?? ?? EB ?? 48 89 F9 48 89 EF E8 ?? ?? ?? ?? 48 89 D9 E8
            ?? ?? ?? ?? 31 C0 48 83 C9 ?? F2 AE 48 89 CE 48 F7 D6 48 89 F1 48 83 C1 ?? E8 ?? ??
            ?? ?? 48 89 EA 48 89 C1 E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ??
            48 89 E9 48 89 C2 48 83 C4 ?? 5B 5E 5F 5D 41 5C 41 5D E9
        }
		$register_service_p1 = {
            57 56 53 48 81 EC ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 31 C0 41 B9 ?? ?? ?? ?? 48 8D 94
            24 ?? ?? ?? ?? 48 89 CB B9 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 48 89 D7 F3 AB 48 8D
            44 24 ?? 48 89 54 24 ?? 48 C7 C1 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 15 ?? ?? ?? ?? 48
            C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 80 BC 24 ?? ?? ?? ?? ?? 48 8B 35 ?? ?? ??
            ?? 0F 85 ?? ?? ?? ?? 48 8D 9C 24 ?? ?? ?? ?? 31 C9 41 B8 ?? ?? ?? ?? 48 89 DA FF 15
            ?? ?? ?? ?? 48 8D 44 24 ?? 45 31 C0 41 B9 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 15 ?? ??
            ?? ?? 48 C7 C1 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? 48 8D 05 ?? ?? ?? ?? 48 8B
            4C 24 ?? 41 B9 ?? ?? ?? ?? 45 31 C0 C7 44 24 ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48
            89 44 24 ?? FF 15 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ??
            45 31 C0 48 89 D9 FF 15 ?? ?? ?? ?? 31 C0 E9 ?? ?? ?? ?? 31 C9 FF D6 48 85 C0 79 ??
            B9 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? EB ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 31 C9 BA ?? ??
            ?? ?? 48 C1 E0 ?? 48 89 9C 24 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 8D 05 ?? ?? ??
            ?? 48 8D 35 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ??
            48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 89 B4 24 ?? ?? ?? ?? 48 8D
        }
		$register_service_p2 = {
            8C 24 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7
            84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ??
            41 B9 ?? ?? ?? ?? 48 89 F2 48 89 1D ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 89 5C 24 ??
            48 8B 35 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 C7 44 24 ?? ?? ?? ?? ?? 48 C7 44 24 ?? ?? ??
            ?? ?? 48 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7
            44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF D6 B9 ?? ?? ?? ?? 48 89 C3 FF 15 ??
            ?? ?? ?? BA ?? ?? ?? ?? 48 89 D9 49 89 C0 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8D
            54 24 ?? 48 89 C1 FF 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 41 B9 ?? ??
            ?? ?? 4C 8B 05 ?? ?? ?? ?? 48 89 5C 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? 48 C7 44 24 ??
            ?? ?? ?? ?? 48 89 44 24 ?? 8B 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ??
            ?? 99 F7 F9 2D ?? ?? ?? ?? 89 44 24 ?? 8B 44 24 ?? 99 F7 F9 31 C9 48 8D 15 ?? ?? ??
            ?? 2D ?? ?? ?? ?? 89 44 24 ?? FF D6 BA ?? ?? ?? ?? 48 89 D9 FF 15 ?? ?? ?? ?? 48 89
            D9 FF 15 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 8D 5C 24 ?? 45 31 C9 45 31 C0 31 D2 48
            89 D9 FF D6 85 C0 74 ?? 48 89 D9 FF 15 ?? ?? ?? ?? 48 89 D9 FF 15 ?? ?? ?? ?? EB ??
            8B 84 24 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 5B 5E 5F C3
        }

	condition:
		uint16(0)==0x5A4D and ( all of ($register_service_p*)) and ($find_files) and ($encrypt_files)
}
