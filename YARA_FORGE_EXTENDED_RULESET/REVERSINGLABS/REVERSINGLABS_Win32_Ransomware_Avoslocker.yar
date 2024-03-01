rule REVERSINGLABS_Win32_Ransomware_Avoslocker : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects AvosLocker ransomware."
		author = "ReversingLabs"
		id = "a803283d-6424-5a64-89e6-c73a3322ba1e"
		date = "2021-10-22"
		modified = "2021-10-22"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.AvosLocker.yara#L1-L108"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4d81b801a95a54a35989c4a985d92578971568d1412f625bca911d0fa1eee1fe"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "AvosLocker"
		tc_detection_factor = 5
		importance = 25

	strings:
		$find_files = {
            53 53 53 51 F7 D0 23 85 ?? ?? ?? ?? 53 50 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 75 ?? FF
            B5 ?? ?? ?? ?? 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 E9 ?? ?? ?? ?? 8B 85 ?? ?? ??
            ?? 8B 48 ?? 2B 08 C1 F9 ?? 89 8D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89
            9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8 ?? ?? ?? ??
            50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83
            C4 ?? F7 D8 1B C0 F7 D0 23 85 ?? ?? ?? ?? 80 38 ?? 75 ?? 8A 48 ?? 84 C9 74 ?? 80 F9
            ?? 75 ?? 38 58 ?? 74 ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 83
            C4 ?? 89 85 ?? ?? ?? ?? 85 C0 75 ?? 38 9D ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? E8 ??
            ?? ?? ?? 59 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 85
            ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 10 8B 40 ?? 2B C2 C1 F8 ?? 3B C8 74 ?? 68 ?? ?? ??
            ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 38 9D ?? ?? ?? ?? 74 ??
            FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 59 8B D8 56 FF 15
        }
		$enum_resources = {
            50 51 6A ?? 6A ?? 6A ?? C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ??
            ?? FF 75 ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F8 85 FF 0F 84 ?? ?? ?? ?? FF 75 ?? 6A ?? 57
            E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 50 57 8D 45 ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0
            0F 85 ?? ?? ?? ?? 33 DB 39 5D ?? 76 ?? 8D 77 ?? 83 7E ?? ?? 0F 85 ?? ?? ?? ?? 83 7E
            ?? ?? 0F 85 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 46 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 85
            ?? ?? ?? ?? 39 46 ?? B9 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 8B D1 0F 45 56 ?? 8B C1 83
            7E ?? ?? 0F 11 85 ?? ?? ?? ?? 0F 45 46 ?? 83 3E ?? 0F 28 05 ?? ?? ?? ?? 89 45 ?? 8B
            C1 0F 45 06 83 7E ?? ?? 0F 11 45 ?? 89 45 ?? 8B C1 0F 28 05 ?? ?? ?? ?? 0F 45 46 ??
            33 C9 0F 11 45 ?? 89 45 ?? 0F 28 05 ?? ?? ?? ?? 0F 11 45 ?? 8A 85 ?? ?? ?? ?? 30 84
            0D ?? ?? ?? ?? 41 83 F9 ?? 72 ?? 52 FF 75 ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? FF 75 ??
            FF 75 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 3E ?? 0F 84 ?? ?? ?? ?? FF 36 E8 ?? ?? ?? ??
            59 83 F8 ?? 0F 86 ?? ?? ?? ?? 8B 06 80 78 ?? ?? 75 ?? B1 ?? C7 45 ?? ?? ?? ?? ?? C7
            45 ?? ?? ?? ?? ?? 33 C0 66 C7 45 ?? ?? ?? C6 45 ?? ?? 30 4C 05 ?? 40 83 F8 ?? 73 ??
            8A 4D ?? EB ?? 8D 45 ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ?? 59 FF 36 8D 8D ?? ?? ?? ?? E8
            ?? ?? ?? ?? 83 65 ?? ?? 50 51 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ??
            C6 45 ?? ?? 83 7D ?? ?? 0F 85 ?? ?? ?? ?? 83 4D ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ??
            ?? EB ?? B1 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 33 C0 C7 45 ?? ?? ?? ?? ??
            C6 45 ?? ?? 30 4C 05 ?? 40 83 F8 ?? 73 ?? 8A 4D ?? EB ?? 8D 45 ?? C6 45 ?? ?? 50 E8
            ?? ?? ?? ?? 59 F7 46 ?? ?? ?? ?? ?? 74 ?? 8D 4E ?? E8 ?? ?? ?? ?? 43 83 C6 ?? 3B 5D
            ?? 0F 82 ?? ?? ?? ?? E9 ?? ?? ?? ?? FF 75 ?? FF 15
        }
		$import_key = {
            50 53 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0
            0F 85 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 50 68 ?? ??
            ?? ?? FF D6 50 53 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? B1 ?? C7 85 ?? ?? ?? ?? ?? ?? ??
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8B C3 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 30 8C 05 ?? ??
            ?? ?? 40 83 F8 ?? 73 ?? 8A 8D ?? ?? ?? ?? EB ?? 8D 85 ?? ?? ?? ?? 88 9D ?? ?? ?? ??
            50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 59 0F 11 85 ?? ?? ?? ??
            59 0F 28 05 ?? ?? ?? ?? 8B CB 0F 11 85 ?? ?? ?? ?? 66 C7 85 ?? ?? ?? ?? ?? ?? 88 9D
            ?? ?? ?? ?? 8A 85 ?? ?? ?? ?? 30 84 0D ?? ?? ?? ?? 41 83 F9 ?? 72 ?? 88 9D ?? ?? ??
            ?? FF D6 50 8D 85 ?? ?? ?? ?? E9 ?? ?? ?? ?? FF 36 8D 45 ?? 89 9D ?? ?? ?? ?? 50 E8
            ?? ?? ?? ?? FF 76 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 8B 8D ??
            ?? ?? ?? 83 C4 ?? 8B D7 50 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ??
            84 C0 75 ?? 0F 28 05 ?? ?? ?? ?? 8B CB 0F 11 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ??
            ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 11 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 C7
            85 ?? ?? ?? ?? ?? ?? 88 9D ?? ?? ?? ?? 8A 85 ?? ?? ?? ?? 30 84 0D ?? ?? ?? ?? 41 83
            F9 ?? 72 ?? 8D 85 ?? ?? ?? ?? 88 9D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 8D 45 ?? 50 E8
            ?? ?? ?? ?? 59 8D 4D ?? 85 C0 74 ?? 88 19 41 83 E8 ?? 75 ?? 39 9D ?? ?? ?? ?? 74 ??
            FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 4D ?? 5F 5E 33 CD 5B E8
        }
		$encrypt_files = {
            50 51 51 FF B5 ?? ?? ?? ?? 51 FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ??
            ?? ?? 8B BD ?? ?? ?? ?? 57 89 BD ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 59 85 F6 0F 84 ??
            ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B CE 85 C0 74 ?? C6 01 ?? 41 83 E8 ?? 75 ?? 8D 85 ?? ??
            ?? ?? 50 E8 ?? ?? ?? ?? 59 83 C0 ?? 74 ?? 39 85 ?? ?? ?? ?? 72 ?? 50 8D 85 ?? ?? ??
            ?? 50 56 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? FF B5 ?? ?? ?? ?? 6A ?? 56 E8 ?? ?? ?? ?? 83
            C4 ?? E8 ?? ?? ?? ?? C7 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ??
            ?? ?? 59 57 40 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 6A ?? FF B5 ?? ?? ?? ?? 6A
            ?? FF B5 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? D1 EF 6A ?? 5A 74 ??
            8B 9D ?? ?? ?? ?? 4B 03 DE 8A 03 8A 0C 32 88 04 32 42 88 0B 4B 3B D7 72 ?? 8B 9D ??
            ?? ?? ?? 8B BD ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 03 C3 56 50 E8 ?? ?? ?? ?? 03 DF 56
            89 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B B5 ?? ?? ??
            ?? 47 81 C6 ?? ?? ?? ?? 89 BD ?? ?? ?? ?? 50 89 B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 D2
            B9 ?? ?? ?? ?? F7 F1 83 C4 ?? 40 3B F8 0F 82
        }

	condition:
		uint16(0)==0x5A4D and ($enum_resources) and ($find_files) and ($import_key) and ($encrypt_files)
}
