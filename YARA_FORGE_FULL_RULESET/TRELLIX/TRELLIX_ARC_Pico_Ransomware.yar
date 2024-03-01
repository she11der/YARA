rule TRELLIX_ARC_Pico_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect Pico Ransomware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "843cac7a-652e-5cbf-a09d-fb4b1eaa8481"
		date = "2018-08-30"
		modified = "2020-08-14"
		reference = "https://twitter.com/siri_urz/status/1035138577934557184"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Pico.yar#L1-L37"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "cc4a9e410d38a29d0b6c19e79223b270e3a1c326b79c03bec73840b37778bc06"
		logic_hash = "bb15e66504f393bcb4b173cb2a4ec65aa13110060f7fb70282330b5f6d72f5ed"
		score = 75
		quality = 20
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/Pico"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "C:\\Users\\rikfe\\Desktop\\Ransomware\\ThanatosSource\\Release\\Ransomware.pdb" fullword ascii
		$s2 = "\\Downloads\\README.txt" fullword ascii
		$s3 = "\\Music\\README.txt" fullword ascii
		$s4 = "\\Videos\\README.txt" fullword ascii
		$s5 = "\\Pictures\\README.txt" fullword ascii
		$s6 = "\\Desktop\\README.txt" fullword ascii
		$s7 = "\\Documents\\README.txt" fullword ascii
		$s8 = "/c taskkill /im " fullword ascii
		$s9 = "\\AppData\\Roaming\\" fullword ascii
		$s10 = "gMozilla/5.0 (Windows NT 6.1) Thanatos/1.1" fullword wide
		$s11 = "AppData\\Roaming" fullword ascii
		$s12 = "\\Downloads" fullword ascii
		$s13 = "operator co_await" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <700KB) and all of them
}
