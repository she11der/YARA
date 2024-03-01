rule REVERSINGLABS_Win32_Ransomware_Ryuk : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Ryuk ransomware."
		author = "ReversingLabs"
		id = "179c9277-0bdc-522a-a822-cf93febff408"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Ryuk.yara#L1-L199"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bf93892b281be20917656e242cbb0f3b3694439556b7e5e40a424ba1aa909105"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "Ryuk"
		tc_detection_factor = 5
		importance = 25

	strings:
		$encrypt_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 
            6A ?? 6A ?? 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8B 55 ?? 52 
            FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? 
            ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 75 ?? 8B 4D ?? 51 FF 15 ?? 
            ?? ?? ?? 33 C0 E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 33 D2 89 55 ?? 0F 57 C0 66 0F 13 
            45 ?? 83 7D ?? ?? 74 ?? 8D 45 ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 8D 55 ?? 52 8B 45 
            ?? 50 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 75 ?? 83 7D ?? ?? 75 ?? 8B 4D ?? 51 FF 15 ?? ?? 
            ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 0F 57 C0 66 0F 13 45 ?? 83 7D ?? ?? 77 ?? 81 7D 
            ?? ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? 6A ?? 6A ?? 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 
            6A ?? 6A ?? 52 50 E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 52 50 E8 ?? ?? ?? ?? 89 45 ?? 
            89 55 ?? 83 7D ?? ?? 72 ?? 77 ?? 81 7D ?? ?? ?? ?? ?? 76 ?? 6A ?? 6A ?? 8B 4D ?? 51 
            8B 55 ?? 52 E8 ?? ?? ?? ?? 6A ?? 6A ?? 52 50 E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 52 
            50 E8 ?? ?? ?? ?? 89 45 ?? 89 55 ?? 83 7D ?? ?? 77 ?? 72 ?? 81 7D ?? ?? ?? ?? ?? 77 
            ?? 83 7D ?? ?? 77 ?? 72 ?? 83 7D ?? ?? 73 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? E9 ?? ?? ?? ?? 83 7D ?? ?? 77 ?? 81 7D ?? ?? ?? ?? ?? 76 ?? 83 7D ?? ?? 77 ?? 72 
            ?? 81 7D ?? ?? ?? ?? ?? 73 ?? 6A ?? 6A ?? 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 6A 
            ?? 6A ?? 52 50 E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 52 50 E8 ?? ?? ?? ?? 89 45 ?? 89 
            55 ?? EB ?? 83 7D ?? ?? 77 ?? 72 ?? 81 7D ?? ?? ?? ?? ?? 73 ?? 6A ?? 6A ?? 8B 55 ?? 
            52 8B 45 ?? 50 E8 ?? ?? ?? ?? 6A ?? 6A ?? 52 50 E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 
            52 50 E8 ?? ?? ?? ?? 89 45 ?? 89 55 ?? 83 7D ?? ?? 77 ?? 72 ?? 81 7D
        }
		$encrypt_files_p2 = {
            77 ?? 83 7D ?? ?? 77 ?? 72 ?? 83 7D ?? ?? 77 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? 
            ?? ?? 8B 4D ?? 89 8D ?? ?? ?? ?? 8B 55 ?? 89 95 ?? ?? ?? ?? 83 7D ?? ?? 77 ?? 72 ?? 
            83 7D ?? ?? 73 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 83 7D 
            ?? ?? 0F 84 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 77 ?? 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 0F 
            86 ?? ?? ?? ?? 8B 4D ?? 81 E9 ?? ?? ?? ?? 89 4D ?? 6A ?? 6A ?? 8B 55 ?? 52 8B 45 ?? 
            50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? B8 ?? 
            ?? ?? ?? E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            6A ?? 8D 95 ?? ?? ?? ?? 52 6A ?? 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 
            89 45 ?? 83 7D ?? ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 
            8B 55 ?? 83 C2 ?? 89 55 ?? 83 7D ?? ?? 0F 83 ?? ?? ?? ?? 83 7D ?? ?? 0F 84 ?? ?? ?? 
            ?? 8B 45 ?? 0F BE 8C 05 ?? ?? ?? ?? 83 F9 ?? 0F 85 ?? ?? ?? ?? 8B 55 ?? 0F BE 84 15 
            ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B 4D ?? 0F BE 94 0D ?? ?? ?? ?? 83 FA ?? 0F 
            85 ?? ?? ?? ?? 8B 45 ?? 0F BE 8C 05 ?? ?? ?? ?? 83 F9 ?? 0F 85 ?? ?? ?? ?? 8B 55 ?? 
            0F BE 84 15 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B 4D ?? 0F BE 94 0D ?? ?? ?? ?? 
            83 FA ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 8D ?? 
            ?? ?? ?? 8B 15 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 66 A1 ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 89 85 ?? ?? ?? ?? 83 BD ?? 
            ?? ?? ?? ?? 75 ?? 8B 45 ?? 89 45 ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 
            8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8B 55 ?? 52 8B 45 ?? 
            50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9
        }
		$encrypt_files_p3 = {
            6A ?? 6A ?? 6A ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 
            ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D 55 ?? 52 6A ?? 68 ?? ?? ?? ?? 8B 45 ?? 50 
            FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? 
            ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 83 7D 
            ?? ?? 77 ?? 81 7D ?? ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 6A ?? 6A ?? 6A 
            ?? 68 ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 50 8B 45 ?? 50 FF 15 ?? ?? 
            ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 8B 
            55 ?? 52 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 
            8D 45 ?? 50 6A ?? 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? 
            ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? 
            ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 
            89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 
            51 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 6A ?? 
            68 ?? ?? ?? ?? 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 89 45 ?? 6A ?? 68
        }
		$encrypt_files_p4 = {
            8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 89 45 ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? EB ?? 8B 4D ?? 83 C1 ?? 89 4D ?? 8B 55 ?? 3B 55 ?? 0F 87 ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 3B 45 ?? 75 ?? 8B 4D ?? 89 4D ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 6A ?? 69 55 ?? ?? ?? ?? ?? 52 8B 45 ?? 50 FF 15 
            ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? 
            ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 8B 
            4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? 
            ?? ?? 75 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? 
            ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 6A ?? 6A ?? 8B 4D ?? 51 6A 
            ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 
            51 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 55 ?? 52 8D 45 ?? 50 8B 4D ?? 
            51 6A ?? 8B 55 ?? 52 6A ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 4D ?? 51 FF 
            15 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 6A 
            ?? 69 45 ?? ?? ?? ?? ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? 
            ?? ?? ?? ?? 75 ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? B8 ?? 
            ?? ?? ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 4D ?? 51 8B 55 ?? 52 8B 45 ?? 
            50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 8B 55 
            ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9
        }
		$encrypt_files_p5 = {
            E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8A 0D ?? ?? ?? ?? 88 4D ?? 33 D2 89 55 
            ?? 89 55 ?? 89 55 ?? 89 55 ?? 88 55 ?? 6A ?? 6A ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? 
            ?? 83 7D ?? ?? 77 ?? 81 7D ?? ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? 33 C9 89 8D ?? ?? ?? ?? 6A ?? 6A ?? 8B 95 ?? ?? ?? ?? 52 8B 85 ?? ?? ?? ?? 50 
            8B 4D ?? 51 FF 15 ?? ?? ?? ?? 8B 55 ?? 89 95 ?? ?? ?? ?? 6A ?? 6A ?? 8D 85 ?? ?? ?? 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 8D ?? ?? ?? ?? 51 8B 95 ?? ?? ?? ?? 52 E8 ?? 
            ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? 
            ?? 51 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 8D 4D ?? 51 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 8D 45 ?? 50 8D 4D ?? 
            51 E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 55 ?? 52 8D 45 ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 50 8D 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 
            75 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 
            ?? ?? ?? ?? 8D 55 ?? 52 6A ?? 6A ?? 6A ?? 8B 45 ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 
            89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 
            50 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8D 8D ?? ?? 
            ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8D 55 ?? 52 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 8B 4D 
            ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 8B
        }
		$encrypt_files_p6 = {
            45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 55 ?? 52 8B 45 ?? 50 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 
            52 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 75 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D 
            ?? 51 FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 83 7D ?? ?? 77 ?? 81 7D ?? ?? 
            ?? ?? ?? 0F 86 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 33 D2 89 55 ?? 0F 57 C0 66 0F 13 45 
            ?? 6A ?? 6A ?? 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? 
            ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? 
            ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 8D 95 ?? ?? 
            ?? ?? 52 6A ?? 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 
            83 BD ?? ?? ?? ?? ?? 75 ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? 
            ?? B8 ?? ?? ?? ?? EB ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8B 55 ?? 
            52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8D 8D 
            ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? EB ?? B8 
            ?? ?? ?? ?? 8B E5 5D C3
        }
		$remote_connection = {
            55 8B EC 81 EC ?? ?? ?? ?? 8B 45 ?? C7 00 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 4D ?? 51 6A ?? 6A ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 
            89 45 ?? 6A ?? 68 ?? ?? ?? ?? 8B 55 ?? 52 6A ?? FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 
            ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8D 4D ?? 51 8B 55 ?? 52 6A ?? 6A ?? 6A ?? E8 
            ?? ?? ?? ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 89 45 ?? EB ?? 8B 4D ?? 8B 51 ?? 
            89 55 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? 83 C0 ?? 89 45 ?? C7 45 ?? ?? ?? ?? 
            ?? 8B 4D ?? 8B 51 ?? 89 55 ?? EB ?? 8B 45 ?? 8B 48 ?? 89 4D ?? 83 7D ?? ?? 0F 84 ?? 
            ?? ?? ?? 8B 55 ?? 83 C2 ?? 89 55 ?? 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 83 C1 ?? 51 E8 ?? 
            ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? B9 ?? 
            ?? ?? ?? 6B D1 ?? 8D 8C 15 ?? ?? ?? ?? 3B C1 74 ?? 68 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 
            52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 0F 57 C0 66 0F 13 45 ?? C7 45 ?? ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 75 ?? 83 C8 ?? E9 ?? ?? 
            ?? ?? 8D 55 ?? 89 55 ?? 8D 45 ?? 50 8B 4D ?? 0F B6 51 ?? 52 E8
        }
		$find_files_p1 = {
            8B FF 55 8B EC 51 8B 4D ?? 53 57 33 DB 8D 51 ?? 66 8B 01 83 C1 ?? 66 3B C3 75 ?? 8B 
            7D ?? 2B CA D1 F9 83 C8 ?? 41 2B C7 89 4D ?? 3B C8 76 ?? 6A ?? 58 EB ?? 56 8D 5F ?? 
            03 D9 6A ?? 53 E8 ?? ?? ?? ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? ?? 
            ?? 83 C4 ?? 85 C0 75 ?? FF 75 ?? 2B DF 8D 04 7E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 85 C0 75 ?? 8B 4D ?? 56 E8 ?? ?? ?? ?? 6A ?? 8B F0 E8 ?? ?? ?? ?? 59 8B C6 5E 5F 
            5B 8B E5 5D C3 33 C0 50 50 50 50 50 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? 
            ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 8B 55 ?? 8B 4D ?? 53 8B 5D ?? 56 57 6A ?? 5E 6A ?? 
            89 95 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 5F EB ?? 0F B7 01 66 3B 85 ?? ?? ?? 
            ?? 74 ?? 66 3B C6 74 ?? 66 3B C7 74 ?? 83 E9 ?? 3B CB 75 ?? 0F B7 31 66 3B F7 75 ?? 
            8D 43 ?? 3B C8 74 ?? 52 33 FF 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 6A ?? 
            8B C6 33 FF 5A 66 3B C2 74 ?? 6A ?? 5A 66 3B C2 74 ?? 6A ?? 5A 66 3B C2 74 ?? 8B C7
        }
		$find_files_p2 = {
            EB ?? 33 C0 40 2B CB 0F B6 C0 D1 F9 41 F7 D8 68 ?? ?? ?? ?? 1B C0 23 C1 89 85 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 57 57 57 50 
            57 53 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 75 ?? 8B 85 ?? ?? ?? ?? 50 57 57 53 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8B F8 83 FE ?? 74 ?? 56 FF 15 ?? ?? ?? ?? 8B C7 8B 4D ?? 5F 5E 33 CD 
            5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 8D ?? ?? ?? ?? 6A ?? 8B 41 ?? 2B 01 C1 F8 ?? 89 85 
            ?? ?? ?? ?? 58 66 39 85 ?? ?? ?? ?? 75 ?? 66 39 BD ?? ?? ?? ?? 74 ?? 66 39 85 ?? ?? 
            ?? ?? 75 ?? 66 39 BD ?? ?? ?? ?? 74 ?? 51 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 50 
            E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 8B 8D 
            ?? ?? ?? ?? 85 C0 6A ?? 58 75 ?? 8B C1 8B 8D ?? ?? ?? ?? 8B 10 8B 40 ?? 2B C2 C1 F8 
            ?? 3B C8 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 
            83 C4 ?? E9
        }

	condition:
		uint16(0)==0x5A4D and ( all of ($find_files_p*)) and ( all of ($encrypt_files_p*)) and ($remote_connection)
}
