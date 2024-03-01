rule REVERSINGLABS_Win32_Ransomware_Gpcode : tc_detection malicious MALWARE FILE
{
	meta:
		description = "Yara rule that detects Gpcode ransomware."
		author = "ReversingLabs"
		id = "168833dd-44ab-59e1-a610-b9219b2907ff"
		date = "2020-07-15"
		modified = "2020-07-15"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/ransomware/Win32.Ransomware.Gpcode.yara#L1-L67"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "329309873977f73a8ebe758018ebc8ba42e15c3c7cbb9a65865631d235f5bb48"
		score = 75
		quality = 90
		tags = "MALWARE, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		tc_detection_type = "Ransomware"
		tc_detection_name = "GPCode"
		tc_detection_factor = 5
		importance = 25

	strings:
		$drive_loop = {
            B9 19 00 00 00 BB 01 00 00 00 D3 E3 23 D8 74 ?? 80
            C1 ?? 88 0D ?? ?? ?? ?? 80 E9 ?? C7 05 ?? ?? ?? ??
            ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? 59 58 49 7D 
        }
		$encrypt_routine = {
            FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? [0-10] 
            E9 ?? ?? ?? ?? 6A ?? [1-10] FF 75 ?? FF 35 ?? ?? 
            ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 0B C0 75 ?? E9 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? [1-10] FF 35 ?? ?? ?? ?? 
            6A ?? 6A ?? 6A ?? FF 35 ?? ?? ?? ?? (E8 | FF 15) 
            ?? ?? ?? ?? 0B C0 75 ?? (EB | E9) [1-4] 6A ?? 
            [2-10] FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 F8 ?? 
            75 ?? [10-40] FF 35 ?? ?? ?? ?? FF 75 ?? E8
        }
		$set_ransom_wallpaper = {
             0F B6 05 ?? ?? ?? ?? 83 F8 01 0F 85 ?? ?? ?? ?? 
             B9 ?? ?? ?? ?? BF ?? ?? ?? ?? 51 57 [2-20] 5F 
             59 25 ?? ?? ?? ?? C1 E8 ?? 83 C0 ?? AA E2 ?? 33 
             C0 AA 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? 
             ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
             68 ?? ?? ?? ?? (E8 | FF 15)
        }
		$read_config_file = {
            55 8B EC 83 C4 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 
            ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? E8 ?? 
            ?? ?? ?? 0B C0 75 04 33 C0 C9 C3 89 45 ?? 50 6A ?? 
            E8 ?? ?? ?? ?? 0B C0 75 04 33 C0 C9 C3 89 45 ?? FF 
            75 ?? 6A ?? E8 ?? ?? ?? ?? 0B C0 75 04 33 C0 C9 C3 
            89 45 ?? 50 E8 ?? ?? ?? ?? 0B C0 75 04 33 C0 C9 C3 
            89 45 ?? FF 75 ?? 6A ?? E8 ?? ?? ?? ?? 0B C0 75 04 
            33 C0 C9 C3 89 45 ?? 8B D8 FF 75 ?? FF 75 ?? FF 75 
            ?? E8 ?? ?? ?? ?? FF 75 ?? E8 ?? ?? ?? ?? 8B 5D ?? 
            6A ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C3 ?? 8B 
            45 ?? 83 E8 ?? 50 53 E8 ?? ?? ?? ?? 8A 03 A2 ?? ?? 
            ?? ?? 83 C3 ?? 8A 03 A2 ?? ?? ?? ?? 83 C3 
        }

	condition:
		uint16(0)==0x5A4D and ($drive_loop and $encrypt_routine and $set_ransom_wallpaper and $read_config_file)
}
