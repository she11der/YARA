rule REVERSINGLABS_Win32_Ransomware_Hakunamatata : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects HakunaMatata ransomware."
		author = "ReversingLabs"
		id = "17438fcd-7a51-5fb6-96ac-38523bc1744f"
		date = "2020-11-11"
		modified = "2020-11-11"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.HakunaMatata.yara#L1-L373"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e363ff93fce286d60a3f5ea20ba3ec03564b7a5321c3f6448cc82187f23e8a9f"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "HakunaMatata"
		tc_detection_factor = 5
		importance = 25

	strings:
		$encrypt_files = {
            55 89 E5 57 56 53 81 EC ?? ?? ?? ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 8B 40 ?? 
            85 C0 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? 89 14 24 89 C1 E8 ?? 
            ?? ?? ?? 83 EC ?? 84 C0 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? 
            ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 
            24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 89 45 ?? 83 7D ?? 
            ?? 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? 
            ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 
            45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 
            EC ?? 85 C0 0F 95 C0 84 C0 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? 89 45 ?? 89 55 ?? 8B 
            45 ?? 8B 40 ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 89 54 24 
            ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 8B 50 ?? 89 D0 C1 E0 ?? 
            01 D0 01 C0 89 45 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? C7 44 24 ?? ?? ?? ?? 
            ?? 8D 45 ?? 89 44 24 ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 
            A1 ?? ?? ?? ?? FF D0 83 EC ?? 85 C0 0F 94 C0 84 C0 74 ?? C7 45 ?? ?? ?? ?? ?? E9 ?? 
            ?? ?? ?? 8B 45 ?? 8B 40 ?? BA ?? ?? ?? ?? 8B 4D ?? 8B 5D ?? 39 DA 72 ?? 39 DA 77 ?? 
            39 C8 76 ?? 89 C8 89 DA 89 45 ?? 8B 55 ?? 8B 45 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 4D ?? 
            89 4C 24 ?? 89 54 24 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 
            83 F8 ?? 0F 94 C0 84 C0 0F 84 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? 8B 45 ?? 89 4C 24 ?? 89 
            54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 89 C6 8B 45 ?? 89 C1 BB 
            ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? 89 CF 31 C7 89 7D ?? 89 DF 31 D7 89 7D ?? 8B 45 ?? 0B 
            45 ?? 85 C0 0F 94 C0 0F B6 C8 8B 55 ?? 8B 45 ?? 89 44 24 ?? 8D 45 ?? 89 44 24 ?? 89 
            F0 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 14 24 
            A1 ?? ?? ?? ?? FF D0 83 EC ?? 89 45 ?? A1 ?? ?? ?? ?? FF D0 89 45 ?? 8B 45 ?? 85 C0 
            79 ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? C7 44 24 ?? ?? ?? ?? ?? 
            8D 4D ?? 89 4C 24 ?? 89 54 24 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 
            83 EC ?? 85 C0 0F 94 C0 84 C0 74 ?? C7 45 ?? ?? ?? ?? ?? 90 EB ?? 8B 4D ?? 8B 5D ?? 
            8B 45 ?? BA ?? ?? ?? ?? 29 C1 19 D3 89 C8 89 DA 89 45 ?? 89 55 ?? 8B 45 ?? BA ?? ?? 
            ?? ?? 01 45 ?? 11 55 ?? 8B 45 ?? 8B 55 ?? 89 C6 83 F6 ?? 89 75 ?? 89 D0 80 F4 ?? 89 
            45 ?? 8B 55 ?? 8B 4D ?? 89 C8 09 D0 85 C0 74 ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 
            8B 45 ?? 85 C0 74 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 8B 45 ?? 
            89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 45 ?? 89 
            04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 83 7D ?? ?? 74 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? 
            ?? EB ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 
            EC ?? 8B 45 ?? 8D 65 ?? 5B 5E 5F 5D C2 
        }
		$encrypt_files_2 = {
            55 89 E5 56 53 81 EC ?? ?? ?? ?? 89 4D ?? 8B 45 ?? 89 85 ?? ?? ?? ?? 8B 45 ?? 89 85 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 8B 40 ?? 85 C0 0F 84 ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? 8B 55 ?? 8D 45 ?? 89 04 24 89 D1 E8 ?? ?? ?? ?? 83 EC ?? 84 C0 0F 84 ?? 
            ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 
            44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 
            24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? C7 44 24 ?? 
            ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 
            C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF 
            D0 83 EC ?? 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 89 
            44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 85 C0 0F 95 C0 84 C0 0F 84 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? 89 45 ?? 89 55 ?? 8B 45 ?? 8B 55 ?? 89 45 ?? 89 55 ?? 
            8B 85 ?? ?? ?? ?? 80 F4 ?? 89 C3 8B 85 ?? ?? ?? ?? 80 F4 ?? 89 C6 89 F0 09 D8 85 C0 
            74 ?? 8B 45 ?? 8B 55 ?? 3B 95 ?? ?? ?? ?? 72 ?? 3B 95 ?? ?? ?? ?? 77 ?? 3B 85 ?? ?? 
            ?? ?? 76 ?? 8B 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 89 45 ?? 89 55 ?? 8B 45 ?? 8B 40 ?? 
            89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 8B 55 ?? 89 44 24 ?? C7 44 24 ?? 
            ?? ?? ?? ?? 89 14 24 E8 ?? ?? ?? ?? 8B 45 ?? 8B 50 ?? 89 D0 C1 E0 ?? 01 D0 01 C0 89 
            45 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 45 ?? 89 
            44 24 ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? 
            FF D0 83 EC ?? 85 C0 0F 94 C0 84 C0 74 ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 
            ?? 8B 40 ?? BA ?? ?? ?? ?? 8B 4D ?? 8B 5D ?? 39 DA 72 ?? 39 DA 77 ?? 39 C8 76 ?? 89 
            C8 89 DA 89 45 ?? 8B 4D ?? 8B 55 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? 89 
            4C 24 ?? 89 54 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 83 F8 ?? 0F 94 
            C0 84 C0 0F 84 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? 8B 45 ?? 89 4C 24 ?? 89 54 24 ?? 89 04 
            24 E8 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 89 C1 BB ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? 
            89 CE 31 C6 89 B5 ?? ?? ?? ?? 89 DE 31 D6 89 B5 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 8B B5 
            ?? ?? ?? ?? 89 D8 09 F0 85 C0 0F 94 C0 88 45 ?? 8B 55 ?? 0F B6 4D ?? 8B 5D ?? 8B 45 
            ?? 89 44 24 ?? 8D 45 ?? 89 44 24 ?? 89 54 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 4C 24 ?? 
            C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 89 45 ?? A1 ?? ?? ?? 
            ?? FF D0 89 45 ?? 8B 45 ?? 85 C0 79 ?? C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 4D ?? 
            8B 55 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? 89 4C 24 ?? 89 54 24 ?? 8B 45 
            ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 85 C0 0F 94 C0 84 C0 74 ?? C7 45 ?? ?? ?? 
            ?? ?? 90 EB ?? 8B 4D ?? 8B 5D ?? 8B 45 ?? BA ?? ?? ?? ?? 29 C1 19 D3 89 C8 89 DA 89 
            45 ?? 89 55 ?? 8B 45 ?? BA ?? ?? ?? ?? 01 45 ?? 11 55 ?? 8B 45 ?? 8B 55 ?? 89 C6 83 
            F6 ?? 89 B5 ?? ?? ?? ?? 89 D0 80 F4 ?? 89 85 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 8B B5 ?? 
            ?? ?? ?? 89 F0 09 D8 85 C0 74 ?? E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? 80 F4 ?? 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 80 F4 ?? 89 85 ?? ?? ?? ?? 8B 9D ?? 
            ?? ?? ?? 8B B5 ?? ?? ?? ?? 89 F0 09 D8 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? 2B 
            45 ?? 1B 55 ?? 89 45 ?? 89 55 ?? 8B 45 ?? 8B 40 ?? 89 C1 BB ?? ?? ?? ?? 8B 45 ?? 8B 
            55 ?? 39 D3 72 ?? 39 D3 77 ?? 39 C1 76 ?? 89 C1 89 D3 89 4D ?? 8B 45 ?? C7 44 24 ?? 
            ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8B 55 ?? 89 54 24 ?? 89 44 24 ?? 8B 45 ?? 89 04 24 
            A1 ?? ?? ?? ?? FF D0 83 EC ?? 83 F8 ?? 0F 94 C0 84 C0 0F 84 ?? ?? ?? ?? 8B 55 ?? 8B 
            45 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 4D ?? 89 4C 24 ?? 89 54 24 ?? 89 44 24 ?? 8B 45 ?? 
            89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 85 C0 0F 94 C0 84 C0 74 ?? C7 45 ?? ?? ?? ?? 
            ?? EB ?? 8B 45 ?? 8B 55 ?? 8B 4D ?? BB ?? ?? ?? ?? 29 C8 19 DA 89 45 ?? 89 55 ?? 8B 
            45 ?? 8B 55 ?? 89 C3 80 F7 ?? 89 9D ?? ?? ?? ?? 89 D0 80 F4 ?? 89 85 ?? ?? ?? ?? 8B 
            9D ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 89 F0 09 D8 85 C0 74 ?? E9 ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 
            8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 8B 
            45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 83 7D ?? ?? 74 ?? 8B 45 ?? 89 04 24 E8 
            ?? ?? ?? ?? EB ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? 
            FF D0 83 EC ?? 8B 45 ?? 8D 65 ?? 5B 5E 5D C2 
        }
		$search_files = {
            E8 ?? ?? ?? ?? 83 EC ?? 85 C0 0F 95 C0 88 45 ?? 80 7D ?? ?? 74 ?? C7 44 24 ?? ?? ?? 
            ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 
            83 EC ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? 83 45 ?? ?? EB ?? A1 ?? 
            ?? ?? ?? FF D0 89 C3 C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 
            04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? 89 1C 24 89 C1 E8 ?? ?? ?? ?? 83 EC 
            ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 
            ?? ?? ?? ?? 83 EC ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? 8B 45 ?? 89 
            C1 E8 ?? ?? ?? ?? 8B 5D ?? 85 DB 74 ?? 89 D9 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 
            89 1C 24 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 
            ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? EB ?? 8D 85 ?? ?? ?? ?? 89 C1 
            E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? EB ?? 90 8D 85 
            ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 85 C0 0F 95 
            C0 84 C0 74 ?? E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF D0 89 45 ?? 83 7D ?? ?? 0F 84 ?? ?? 
            ?? ?? A1 ?? ?? ?? ?? FF D0 89 C3 C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? 89 1C 24 89 C1 E8 ?? ?? 
            ?? ?? 83 EC ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? C7 44 24 ?? ?? ?? 
            ?? ?? 89 04 24 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? C7 
            04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 
            ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC ?? 83 7D ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? 05 ?? 
            ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 85 C0 74 ?? B8 ?? ?? ?? ?? EB ?? B8 ?? ?? ?? ?? 84 C0 
            74 ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 89 C2 8B 85 ?? ?? ?? ?? 89 14 24 89 C1 
            E8 ?? ?? ?? ?? 83 EC ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            89 C2 8B 45 ?? 89 04 24 89 D1 E8 ?? ?? ?? ?? 83 EC ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 
            ?? ?? ?? ?? 83 EC ?? C7 04 24 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 EC ?? C7 44 24 ?? 
            ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 
        }
		$search_files_2 = {
            FF 15 ?? ?? ?? ?? EB ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? FF 15 ?? ?? ?? 
            ?? 89 C3 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 
            04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 50 ?? 81 C2 ?? ?? ?? ?? 8B 42 ?? 
            83 E0 ?? 83 C8 ?? 89 42 ?? 89 1C 24 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 89 C3 8B 
            00 89 DA 03 50 ?? 8B 42 ?? 83 E0 ?? 83 C8 ?? 89 42 ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? 
            ?? ?? 89 C1 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 FF 15 ?? ?? ?? 
            ?? 83 EC ?? 83 BD ?? ?? ?? ?? ?? 74 ?? 83 BB ?? ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? 
            89 04 24 89 D9 E8 ?? ?? ?? ?? 83 EC ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 
            04 24 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 89 04 24 E8 ?? ?? ?? ?? 89 C1 E8 ?? ?? 
            ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 
            24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 B9 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 EC ?? 89 04 24 E8 ?? ?? ?? ?? 89 C1 E8 
        }
		$remote_connection = {
            55 89 E5 53 81 EC ?? ?? ?? ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 89 44 24 ?? C7 
            04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F0 ?? 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 
            ?? ?? ?? ?? 8B 45 ?? 8B 00 89 45 ?? 8D 45 ?? 89 44 24 ?? 8D 45 ?? 89 44 24 ?? 8D 45 
            ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 
            8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 89 45 ?? 83 7D ?? ?? 74 ?? 81 7D ?? ?? ?? 
            ?? ?? 75 ?? 8B 45 ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 39 45 ?? 77 ?? 8D 45 ?? 
            89 C1 E8 ?? ?? ?? ?? 8B 45 ?? 8B 10 8D 45 ?? 8D 4D ?? 89 4C 24 ?? 89 14 24 89 C1 E8 
            ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 8D 50 ?? 8D 45 ?? 89 04 24 89 D1 E8 ?? ?? ?? ?? 83 EC 
            ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 83 45 ?? ?? 83 45 ?? 
            ?? EB ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 81 7D ?? ?? ?? ?? ?? 75 ?? E9 ?? 
            ?? ?? ?? 8D 45 ?? 83 C0 ?? 89 C1 E8 ?? ?? ?? ?? 85 C0 0F 95 C0 84 C0 74 ?? 8B 45 ?? 
            05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 8D 50 ?? 8D 45 ?? 89 04 24 89 D1 E8 
            ?? ?? ?? ?? 83 EC ?? 8B 45 ?? 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 90 8D 45 ?? 89 
            C1 E8 ?? ?? ?? ?? EB ?? 89 C3 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? EB ?? 89 C3 8D 45 ?? 89 
            C1 E8 ?? ?? ?? ?? EB ?? 89 C3 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 89 D8 89 04 24 E8 ?? ?? 
            ?? ?? 90 8B 5D ?? C9 C2
        }
		$remote_connection_2 = {
            55 89 E5 57 56 53 83 EC ?? 89 4D ?? 8B 5D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 45 ?? 89 44 24 ?? C7 04 24 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 8B 03 89 45 ?? EB ?? 83 EC ?? 89 45 ?? 85 C0 74 ?? 3D ?? ?? 
            ?? ?? 74 ?? 81 7D ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? 8D 45 ?? 89 
            44 24 ?? 8D 45 ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? C7 44 24 
            ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? EB ?? 8B 45 ?? 89 45 ?? 83 7D ?? ?? 
            74 ?? BE ?? ?? ?? ?? 8D 7D ?? EB ?? 83 EC ?? 8D 45 ?? 89 04 24 8D 4D ?? E8 ?? ?? ?? 
            ?? 83 EC ?? 8B 45 ?? 39 F8 74 ?? 89 04 24 E8 ?? ?? ?? ?? 83 C6 ?? 39 75 ?? 72 ?? 8B 
            45 ?? 8B 5C B0 ?? 89 7D ?? B8 ?? ?? ?? ?? 85 DB 74 ?? 89 1C 24 E8 ?? ?? ?? ?? 8D 04 
            43 C6 44 24 ?? ?? 89 44 24 ?? 89 1C 24 8D 4D ?? E8 ?? ?? ?? ?? EB ?? 8B 45 ?? 89 04 
            24 E8 ?? ?? ?? ?? 83 EC ?? E9 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? C1 F8 ?? 69 C0 ?? ?? ?? 
            ?? 85 C0 74 ?? 8B 7D ?? 8D 9F ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 47 ?? 3B 47 ?? 
            74 ?? 85 C0 74 ?? 8B 55 ?? 89 10 8D 48 ?? 8D 45 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 
            8B 45 ?? 83 40 ?? ?? 89 1C 24 E8 ?? ?? ?? ?? EB ?? 8B 4D ?? 83 C1 ?? 8D 45 ?? 89 04 
            24 E8 ?? ?? ?? ?? 83 EC ?? EB ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C2
        }
		$encrypt_files_3 = {
            55 57 56 53 83 EC ?? 8B 41 ?? 85 C0 75 ?? 8B 84 24 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? 
            ?? BE ?? ?? ?? ?? 89 F0 83 C4 ?? 5B 5E 5F 5D C2 ?? ?? 89 CB C7 44 24 ?? ?? ?? ?? ?? 
            8D 54 24 ?? 89 54 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 FF 
            15 ?? ?? ?? ?? 83 EC ?? 85 C0 74 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 
            C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? 
            ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 89 04 24 FF 15 ?? ?? ?? ?? 83 EC ?? 89 C7 BE ?? ?? 
            ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 
            44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? 
            ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 89 04 24 FF 15 ?? ?? ?? ?? 83 EC ?? 89 C2 89 44 24 ?? 
            83 F8 ?? 74 ?? 8D 44 24 ?? 89 44 24 ?? 89 14 24 FF 15 ?? ?? ?? ?? 83 EC ?? 89 C6 85 
            C0 75 ?? 8B 44 24 ?? 89 04 24 FF 15 ?? ?? ?? ?? 83 EC ?? 89 3C 24 FF 15 ?? ?? ?? ?? 
            83 EC ?? 8B 44 24 ?? 89 04 24 FF 15 ?? ?? ?? ?? 83 EC ?? 85 F6 0F 84 ?? ?? ?? ?? 8B 
            84 24 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 
            44 24 ?? ?? ?? ?? ?? 8B 44 24 ?? 8B 54 24 ?? 89 44 24 ?? 89 54 24 ?? 8B 43 ?? 89 04 
            24 E8 ?? ?? ?? ?? 89 44 24 ?? 8B 73 ?? 89 74 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 
            E8 ?? ?? ?? ?? 8D 04 B6 01 C0 89 44 24 ?? 89 04 24 E8 ?? ?? ?? ?? 89 C5 C7 44 24 ?? 
            ?? ?? ?? ?? 8D 44 24 ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 89 
            44 24 ?? 89 3C 24 FF 15 ?? ?? ?? ?? 83 EC ?? 89 C6 85 C0 0F 84 ?? ?? ?? ?? 8B 44 24 
            ?? 8B 54 24 ?? 8B 0D ?? ?? ?? ?? 89 4C 24 ?? 89 7C 24 ?? 89 C6 89 D7 89 5C 24 ?? E9 
            ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 44 24 ?? 89 44 24 ?? 89 5C 24 ?? 8B 44 24 ?? 
            89 44 24 ?? 8B 4C 24 ?? 89 0C 24 FF 54 24 ?? 83 EC ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 89 
            5C 24 ?? 8B 44 24 ?? 89 44 24 ?? 89 2C 24 E8 ?? ?? ?? ?? 89 5C 24 ?? 89 5C 24 ?? C7 
            44 24 ?? ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 8D 44 24 ?? 89 44 24 ?? 89 6C 24 ?? C7 
            44 24 ?? ?? ?? ?? ?? 89 DA 31 F2 09 FA 0F 94 C0 0F B6 C0 89 44 24 ?? C7 44 24 ?? ?? 
            ?? ?? ?? 8B 44 24 ?? 89 04 24 FF 15 ?? ?? ?? ?? 83 EC ?? 89 C3 FF 15 ?? ?? ?? ?? 85 
            C0 78 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 44 24 ?? 89 44 24 ?? 8B 44 24 ?? 89 44 24 ?? 89 
            6C 24 ?? 8B 4C 24 ?? 89 0C 24 FF 15 ?? ?? ?? ?? 83 EC ?? 85 C0 74 ?? 2B 74 24 ?? 1B 
            7C 24 ?? 89 FA 09 F2 74 ?? 8B 44 24 ?? 8B 58 ?? B8 ?? ?? ?? ?? 39 F8 0F 82 ?? ?? ?? 
            ?? 39 F3 0F 47 DE E9 ?? ?? ?? ?? 8B 7C 24 ?? 89 DE EB ?? 8B 7C 24 ?? BE ?? ?? ?? ?? 
            85 ED 74 ?? 89 2C 24 E8 ?? ?? ?? ?? 8B 44 24 ?? 85 C0 0F 84 ?? ?? ?? ?? 89 04 24 E8 
            ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 7C 24 ?? BE ?? ?? ?? ?? EB
        }
		$encrypt_files_4 = {
            FF 15 ?? ?? ?? ?? 83 EC ?? 89 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 88 ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 
            34 24 89 54 24 ?? 89 44 24 ?? 89 4C 24 ?? FF 95 ?? ?? ?? ?? 83 EC ?? 85 C0 0F 84 ?? 
            ?? ?? ?? 8B 85 ?? ?? ?? ?? 29 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 19 95 ?? ?? ?? ?? 8B 
            8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 89 D0 89 CA 09 C2 0F 84 ?? ?? ?? ?? 31 D2 3B 95 ?? 
            ?? ?? ?? 8B 43 ?? 89 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 72 ?? 77 ?? 8B 8D ?? ?? ?? ?? 
            39 C8 76 ?? 8B 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 
            89 85 ?? ?? ?? ?? 89 44 24 ?? 8D 8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            C7 44 24 ?? ?? ?? ?? ?? 89 4C 24 ?? 89 54 24 ?? 89 04 24 FF 15 ?? ?? ?? ?? 83 EC ?? 
            83 F8 ?? 0F 84 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? 89 04 24 E8 ?? ?? ?? ?? 89 34 24 8B 35 ?? ?? ?? ?? FF D6 8B 85 ?? ?? ?? ?? 83 EC 
            ?? 89 04 24 FF D6 8B 85 ?? ?? ?? ?? 83 EC ?? 89 04 24 FF 15 ?? ?? ?? ?? 8B 8D ?? ?? 
            ?? ?? 83 EC ?? 85 C9 0F 84 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? C7 
            04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? C7 04 24 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 40 ?? 8B 88 ?? ?? ?? ?? 85 C9 74 ?? 8B 01 C7 
            04 24 ?? ?? ?? ?? FF 50 ?? 83 EC ?? 0F B7 C0 B9 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 
            83 EC ?? 89 C1 E8 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            89 04 24 FF 15 
        }
		$search_files_3 = {
            FF 15 ?? ?? ?? ?? 83 EC ?? 85 C0 0F 84 ?? ?? ?? ?? F6 85 ?? ?? ?? ?? ?? 75 ?? 8B 85 
            ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 FF D7 83 
            EC ?? 85 C0 0F 84 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? ?? EB ?? 90 8D B4 26 ?? ?? ?? ?? 8B 
            85 ?? ?? ?? ?? 83 C3 ?? 8B 50 ?? 8B 40 ?? 89 85 ?? ?? ?? ?? 29 D0 C1 F8 ?? 69 C0 ?? 
            ?? ?? ?? 39 C3 0F 83 ?? ?? ?? ?? 8D 04 5B 8D 34 C5 ?? ?? ?? ?? 8B 04 C2 89 44 24 ?? 
            8B 85 ?? ?? ?? ?? 89 04 24 FF D7 83 EC ?? 85 C0 74 ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? 8B 
            1C 30 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? C7 04 
            24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 DB 0F 84 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 5C 
            24 ?? 89 44 24 ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 40 ?? 8B 88 
            ?? ?? ?? ?? 85 C9 0F 84 ?? ?? ?? ?? 8B 01 C7 04 24 ?? ?? ?? ?? FF 50 ?? 83 EC ?? 0F 
            B7 C0 B9 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 89 C1 E8 ?? ?? ?? ?? 31 F6 E9 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 
            ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 83 EC ?? 89 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 5C 24 
            ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? 
            ?? E9 ?? ?? ?? ?? 90 8D 74 26 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 
            E8
        }
		$install_service = {
            FF 15 ?? ?? ?? ?? 83 EC ?? 85 C0 89 C1 89 44 24 ?? 0F 84 ?? ?? ?? ?? 8B 84 24 ?? ?? 
            ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 0C 24 89 44 24 ?? FF 15 ?? ?? ?? ?? 83 EC ?? 85 C0 
            89 C3 0F 84 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? 8D 6C 24 ?? 8D 7C 24 ?? C7 44 24 ?? 
            ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 6C 24 ?? 89 7C 24 ?? 89 44 24 ?? FF D0 83 EC 
            ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 44 24 ?? 83 E0 ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? A1 ?? ?? 
            ?? ?? 89 44 24 ?? FF D0 8B 74 24 ?? 89 44 24 ?? 83 7C 24 ?? ?? 0F 85 ?? ?? ?? ?? B8 
            ?? ?? ?? ?? F7 64 24 ?? B8 ?? ?? ?? ?? C1 EA ?? 81 FA ?? ?? ?? ?? 0F 47 D0 B8 ?? ?? 
            ?? ?? 81 FA ?? ?? ?? ?? 0F 42 D0 89 14 24 FF 15 ?? ?? ?? ?? 83 EC ?? 89 6C 24 ?? C7 
            44 24 ?? ?? ?? ?? ?? 89 7C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 FF 54 24 ?? 83 EC 
            ?? 85 C0 74 ?? 3B 74 24 ?? 8B 44 24 ?? 72 ?? FF D0 2B 44 24 ?? 3B 44 24 ?? 76 ?? 89 
            1C 24 8B 1D ?? ?? ?? ?? FF D3 83 EC ?? 8B 44 24 ?? 89 04 24 FF D3 83 EC ?? 83 C4 ?? 
            5B 5E 5F 5D C2 ?? ?? 8D B4 26 ?? ?? ?? ?? 8B 44 24 ?? 89 04 24 FF 15 ?? ?? ?? ?? 83 
            EC ?? 83 C4 ?? 5B 5E 5F 5D C2 ?? ?? 8D B6 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 
            24 ?? ?? ?? ?? ?? 89 1C 24 FF 15 ?? ?? ?? ?? 83 EC ?? 85 C0 74 ?? 89 6C 24 ?? C7 44 
            24 ?? ?? ?? ?? ?? 89 7C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 FF 54 24 ?? 83 EC ?? 
            85 C0 0F 84 ?? ?? ?? ?? 8D B6 ?? ?? ?? ?? 8B 44 24 ?? FF D0 8B 74 24 ?? 89 44 24 ?? 
            83 7C 24 ?? ?? 0F 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? F7 64 24 ?? B8 ?? ?? ?? ?? C1 EA ?? 
            81 FA ?? ?? ?? ?? 0F 47 D0 B8 ?? ?? ?? ?? 81 FA ?? ?? ?? ?? 0F 42 D0 89 14 24 FF 15 
            ?? ?? ?? ?? 83 EC ?? 89 6C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 7C 24 ?? C7 44 24 ?? ?? 
            ?? ?? ?? 89 1C 24 FF 54 24 ?? 83 EC ?? 85 C0 0F 84 ?? ?? ?? ?? 3B 74 24 ?? 72 ?? 8B 
            44 24 ?? FF D0 2B 44 24 ?? 3B 44 24 ?? 76 ?? E9
        }
		$encrypt_files_5 = {
            FF 15 ?? ?? ?? ?? 83 EC ?? 89 C7 BE ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? C7 44 24 
            ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? 
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 89 04 24 FF 
            15 ?? ?? ?? ?? 83 EC ?? 89 C2 89 44 24 ?? 83 F8 ?? 74 ?? 8D 44 24 ?? 89 44 24 ?? 89 
            14 24 FF 15 ?? ?? ?? ?? 83 EC ?? 89 C6 85 C0 75 ?? 8B 44 24 ?? 89 04 24 FF 15 ?? ?? 
            ?? ?? 83 EC ?? 89 3C 24 FF 15 ?? ?? ?? ?? 83 EC ?? 8B 44 24 ?? 89 04 24 FF 15 ?? ?? 
            ?? ?? 83 EC ?? 85 F6 0F 84 ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 
            E9 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 44 24 ?? 8B 54 24 
            ?? 89 44 24 ?? 89 54 24 ?? 8B 43 ?? 89 04 24 E8 ?? ?? ?? ?? 89 44 24 ?? 8B 73 ?? 89 
            74 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 04 B6 01 C0 89 44 24 ?? 
            89 04 24 E8 ?? ?? ?? ?? 89 C5 C7 44 24 ?? ?? ?? ?? ?? 8D 44 24 ?? 89 44 24 ?? C7 44 
            24 ?? ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 89 44 24 ?? 89 3C 24 FF 15 ?? ?? ?? ?? 83 EC 
            ?? 89 C6 85 C0 0F 84 ?? ?? ?? ?? 8B 44 24 ?? 8B 54 24 ?? 8B 0D ?? ?? ?? ?? 89 4C 24 
            ?? 89 7C 24 ?? 89 C6 89 D7 89 5C 24 ?? E9 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 44 
            24 ?? 89 44 24 ?? 89 5C 24 ?? 8B 44 24 ?? 89 44 24 ?? 8B 4C 24 ?? 89 0C 24 FF 54 24 
            ?? 83 EC ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 89 5C 24 ?? 8B 44 24 ?? 89 44 24 ?? 89 2C 24 
            E8 ?? ?? ?? ?? 89 5C 24 ?? 89 5C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 
            ?? 8D 44 24 ?? 89 44 24 ?? 89 6C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 DA 31 F2 09 FA 0F 
            94 C0 0F B6 C0 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8B 44 24 ?? 89 04 24 FF 15 ?? ?? 
            ?? ?? 83 EC ?? 89 C3 FF 15 ?? ?? ?? ?? 85 C0 78 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 44 24 
            ?? 89 44 24 ?? 8B 44 24 ?? 89 44 24 ?? 89 6C 24 ?? 8B 4C 24 ?? 89 0C 24 FF 15
        }
		$search_files_4 = {
            FF 15 ?? ?? ?? ?? EB ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? FF 15 ?? ?? ?? 
            ?? 89 C3 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 
            04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 50 ?? 81 C2 ?? ?? ?? ?? 8B 42 ?? 
            83 E0 ?? 83 C8 ?? 89 42 ?? 89 1C 24 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 89 C3 8B 
            00 89 DA 03 50 ?? 8B 42 ?? 83 E0 ?? 83 C8 ?? 89 42 ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? 
            ?? ?? 89 C1 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 FF 15 ?? ?? ?? 
            ?? 83 EC ?? 83 BD ?? ?? ?? ?? ?? 74 ?? 83 BB ?? ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? 
            89 04 24 89 D9 E8 ?? ?? ?? ?? 83 EC ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 
            04 24 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 89 04 24 E8 ?? ?? ?? ?? 89 C1 E8 ?? ?? 
            ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 
            24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 B9 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 EC ?? 89 04 24 E8 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 3B BD ?? 
            ?? ?? ?? 75 ?? EB ?? 83 EC ?? 83 C7 ?? 39 BD ?? ?? ?? ?? 74 ?? 8B 45 ?? 89 44 24 ?? 
            89 3C 24 89 D9 E8 ?? ?? ?? ?? EB ?? BE ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 ?? ?? ?? 
            ?? 39 D0 74 ?? 89 04 24 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? 
            ?? ?? 8D 95 ?? ?? ?? ?? 39 D0 74 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 95 
            ?? ?? ?? ?? 39 D0 74 ?? 89 04 24 E8 ?? ?? ?? ?? 89 F0 8D 65 ?? 5B 5E 5F 5D C2 
        }
		$remote_connection_3 = {
            55 89 E5 57 56 53 83 EC ?? 89 4D ?? 8B 5D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 45 ?? 89 44 24 ?? C7 04 24 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 8B 03 89 45 ?? EB ?? 83 EC ?? 89 45 ?? 85 C0 74 ?? 3D ?? ?? 
            ?? ?? 74 ?? 81 7D ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? 8D 45 ?? 89 
            44 24 ?? 8D 45 ?? 89 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 8D 45 ?? 89 44 24 ?? C7 44 24 
            ?? ?? ?? ?? ?? 8B 45 ?? 89 04 24 E8 ?? ?? ?? ?? EB ?? 8B 45 ?? 89 45 ?? 83 7D ?? ?? 
            74 ?? BE ?? ?? ?? ?? 8D 7D ?? EB ?? 83 EC ?? 8D 45 ?? 89 04 24 8D 4D ?? E8 ?? ?? ?? 
            ?? 83 EC ?? 8B 45 ?? 39 F8 74 ?? 89 04 24 E8 ?? ?? ?? ?? 83 C6 ?? 39 75 ?? 72 ?? 8B 
            45 ?? 8B 5C B0 ?? 89 7D ?? B8 ?? ?? ?? ?? 85 DB 74 ?? 89 1C 24 E8 ?? ?? ?? ?? 8D 04 
            43 C6 44 24 ?? ?? 89 44 24 ?? 89 1C 24 8D 4D ?? E8 ?? ?? ?? ?? EB ?? 8B 45 ?? 89 04 
            24 E8 ?? ?? ?? ?? 83 EC ?? E9 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? C1 F8 ?? 69 C0 ?? ?? ?? 
            ?? 85 C0 74 ?? 8B 7D ?? 8D 9F ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 47 ?? 3B 47 ?? 
            74 ?? 85 C0 74 ?? 8B 55 ?? 89 10 8D 48 ?? 8D 45 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 
            8B 45 ?? 83 40 ?? ?? 89 1C 24 E8 ?? ?? ?? ?? EB ?? 8B 4D ?? 83 C1 ?? 8D 45 ?? 89 04 
            24 E8 ?? ?? ?? ?? 83 EC ?? EB ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C2 ?? 
            ?? 89 C3 8B 45 ?? 8D 55 ?? 39 D0 74 ?? 89 04 24 E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? 
            ?? 89 1C 24 E8 ?? ?? ?? ?? 89 C3 EB ?? 53 83 EC ?? 8B 5C 24 ?? 8D 43 ?? 89 04 24 8B 
            0B E8 ?? ?? ?? ?? 83 EC ?? C7 44 24 ?? ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? C7 04 24 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C4 ?? 5B C3 
        }

	condition:
		uint16(0)==0x5A4D and (($search_files and $encrypt_files and $remote_connection) or ($encrypt_files_2 and $remote_connection and $search_files) or ($search_files_2 and $encrypt_files_3 and $remote_connection_2) or ($install_service and $search_files_3 and $encrypt_files_4) or ($search_files_4 and $encrypt_files_5 and $remote_connection_3))
}
