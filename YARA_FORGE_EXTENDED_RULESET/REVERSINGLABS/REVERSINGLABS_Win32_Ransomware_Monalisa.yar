rule REVERSINGLABS_Win32_Ransomware_Monalisa : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Monalisa ransomware."
		author = "ReversingLabs"
		id = "34addb63-2426-59a2-b79b-052a9161d361"
		date = "2022-05-13"
		modified = "2022-05-13"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Monalisa.yara#L1-L83"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0bcb79dff111ec05ac93bbe9a777546bd6234dc60d9f6982c03cd0bc3b26b038"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Monalisa"
		tc_detection_factor = 5
		importance = 25

	strings:
		$find_files = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? 53 56 A1 ?? ?? ?? ?? 33
            C5 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B 75 ?? 83 EC ?? C7 45 ?? ?? ?? ?? ?? 8B CC 89 65
            ?? 8D 45 ?? B3 ?? 51 50 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC 89 65 ?? 33 C0 6A
            ?? 68 ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 66 89 01 E8 ?? ?? ?? ??
            83 EC ?? C6 45 ?? ?? 8D 45 ?? 8B CC 50 E8 ?? ?? ?? ?? 8A D3 88 5D ?? 8B CE E8 ?? ??
            ?? ?? 8B 55 ?? 83 C4 ?? 83 FA ?? 72 ?? 8B 4D ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ??
            ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? ?? ?? ??
            83 C4 ?? 33 C0 C7 45 ?? ?? ?? ?? ?? 8D 4D ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? E8 ??
            ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5E 5B 8B E5 5D C3
        }
		$write_proc_mem = {
            8D 45 ?? 50 FF 76 ?? 8B 46 ?? 03 C7 50 8B 06 03 45 ?? 50 FF 75 ?? FF 15 ?? ?? ?? ??
            85 C0 0F 84 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 3E 0F B7 41 ?? 48 3B D8 75 ?? 8B 51 ??
            EB ?? 8B 4D ?? 8B 35 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 56 ?? 8B 4E ?? 2B D7 8B C1 25 ??
            ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? EB ?? 8B C1 25 ?? ?? ?? ?? 3D ?? ?? ??
            ?? 75 ?? B8 ?? ?? ?? ?? EB ?? 8B C1 25 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? B8 ?? ?? ??
            ?? EB ?? 8B C1 25 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? EB ?? F7 C1 ?? ??
            ?? ?? 74 ?? B8 ?? ?? ?? ?? EB ?? F7 C1 ?? ?? ?? ?? 74 ?? B8 ?? ?? ?? ?? EB ?? 85 C9
            B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 0F 48 C1 8D 4D ?? 51 50 8B 45 ?? 52 03 C7 50 FF 75 ??
            FF 15
        }
		$encrypt_files = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? A1 ?? ?? ?? ?? 33 C5 50
            8D 45 ?? 64 A3 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B C1 83 F8 ?? 0F 82 ??
            ?? ?? ?? 83 3D ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 51 0F 43 05 ?? ?? ?? ?? 50 6A ?? 68 ??
            ?? ?? ?? 51 FF 75 ?? 8D 4D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? C7 45 ?? ?? ??
            ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 05 ?? ?? ?? ?? ?? ?? ??
            ?? 0F 10 00 0F 11 05 ?? ?? ?? ?? F3 0F 7E 40 ?? 66 0F D6 05 ?? ?? ?? ?? C7 40 ?? ??
            ?? ?? ?? C7 40 ?? ?? ?? ?? ?? 66 89 08 8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 8D 14 55 ??
            ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77
            ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64
            89 0D ?? ?? ?? ?? 59 8B E5 5D C3
        }
		$generate_key = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89
            45 ?? 56 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B 75 ??
            8B 0C 88 A1 ?? ?? ?? ?? 3B 81 ?? ?? ?? ?? 7F ?? 56 FF 75 ?? FF 35 ?? ?? ?? ?? FF 15
            ?? ?? ?? ?? 85 C0 74 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5E 8B 4D ?? 33 CD E8 ?? ??
            ?? ?? 8B E5 5D C2 ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 3D ?? ?? ?? ?? ??
            75 ?? B9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ??
            ?? 68 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 68 ?? ?? ?? ??
            8D 4D ?? E8 ?? ?? ?? ?? 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 68
            ?? ?? ?? ?? 8D 45 ?? 50 E8
        }

	condition:
		uint16(0)==0x5A4D and ($find_files) and ($write_proc_mem) and ($generate_key) and ($encrypt_files)
}