import "pe"

rule TRELLIX_ARC_Badrabbit_Ransomware : RANSOMWARE FILE
{
	meta:
		description = "Rule to detect Bad Rabbit Ransomware"
		author = "Marc Rivero | McAfee ATR Team"
		id = "d6e78c14-0913-5eed-be15-a6d1a8cd1a8d"
		date = "2024-02-01"
		modified = "2020-08-14"
		reference = "https://securelist.com/bad-rabbit-ransomware/82851/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_BadRabbit.yar#L49-L101"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "7536f021ce7fede0f1a2bf2f4ebc7d6e7269a6dd63005cab1fc6a309a71c61c0"
		score = 75
		quality = 43
		tags = "RANSOMWARE, FILE"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/BadRabbit"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\" -id %u && exit\"" fullword wide
		$s2 = "C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\" fullword wide
		$s3 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
		$s4 = "need to do is submit the payment and get the decryption password." fullword wide
		$s5 = "schtasks /Create /SC once /TN drogon /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
		$s6 = "rundll32 %s,#2 %s" fullword ascii
		$s7 = " \\\"C:\\Windows\\%s\\\" #1 " fullword wide
		$s8 = "Readme.txt" fullword wide
		$s9 = "wbem\\wmic.exe" fullword wide
		$s10 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide
		$og1 = { 39 74 24 34 74 0a 39 74 24 20 0f 84 9f }
		$og2 = { 74 0c c7 46 18 98 dd 00 10 e9 34 f0 ff ff 8b 43 }
		$og3 = { 8b 3d 34 d0 00 10 8d 44 24 28 50 6a 04 8d 44 24 }
		$oh1 = { 39 5d fc 0f 84 03 01 00 00 89 45 c8 6a 34 8d 45 }
		$oh2 = { e8 14 13 00 00 b8 ff ff ff 7f eb 5b 8b 4d 0c 85 }
		$oh3 = { e8 7b ec ff ff 59 59 8b 75 08 8d 34 f5 48 b9 40 }
		$oj4 = { e8 30 14 00 00 b8 ff ff ff 7f 48 83 c4 28 c3 48 }
		$oj5 = { ff d0 48 89 45 e0 48 85 c0 0f 84 68 ff ff ff 4c }
		$oj6 = { 85 db 75 09 48 8b 0e ff 15 34 8f 00 00 48 8b 6c }
		$ok1 = { 74 0c c7 46 18 c8 4a 40 00 e9 34 f0 ff ff 8b 43 }
		$ok2 = { 68 f8 6c 40 00 8d 95 e4 f9 ff ff 52 ff 15 34 40 }
		$ok3 = { e9 ef 05 00 00 6a 10 58 3b f8 73 30 8b 45 f8 85 }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and ( all of ($s*) and all of ($og*)) or all of ($oh*) or all of ($oj*) or all of ($ok*)
}
