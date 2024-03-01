import "pe"

rule TRELLIX_ARC_Win_Netwalker_Reflective_Dll_Injection_Decoded : RANSOMWARE
{
	meta:
		description = "Rule to detect Reflective DLL Injection Powershell Script dropping Netwalker, after hexadecimal decoded and xor decrypted "
		author = "McAfee ATR Team"
		id = "9562c0b9-e7ac-5b96-99cc-1df91cb617af"
		date = "2020-05-28"
		modified = "2020-11-20"
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/netwalker-fileless-ransomware-injected-via-reflective-loading/ | https://news.sophos.com/en-us/2020/05/27/netwalker-ransomware-tools-give-insight-into-threat-actor/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_netwalker.yar#L77-L140"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "fd29001b8b635e6c51270788bab7af0bb5adba6917c278b93161cfc2bc7bd6ae"
		logic_hash = "e99c045f39e7933e877a4df7793aa5ea6be5a782bb079419501929ba99844dec"
		score = 75
		quality = 30
		tags = "RANSOMWARE"
		rule_version = "v1"
		malware_type = "ransomware"

	strings:
		$api0 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 20 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 22 29 5d }
		$api1 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 22 29 5d }
		$api2 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 4c 6f 61 64 4c 69 62 72 61 72 79 41 22 29 5d }
		$api3 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 22 29 5d }
		$api4 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 56 69 72 74 75 61 6c 46 72 65 65 22 29 5d }
		$api5 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 22 29 5d }
		$api6 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 43 6c 6f 73 65 48 61 6e 64 6c 65 22 29 5d }
		$api7 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 20 53 65 74 4c 61 73 74 45 72 72 6f 72 3d 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 22 29 5d }
		$api8 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 20 53 65 74 4c 61 73 74 45 72 72 6f 72 3d 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 22 29 5d }
		$api9 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 20 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 4f 70 65 6e 50 72 6f 63 65 73 73 22 29 5d }
		$api10 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 22 29 5d }
		$artifact0 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 22 29 5d }
		$artifact1 = { 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 50 74 72 54 6f 53 74 72 75 63 74 75 72 65 }
		$artifact2 = { 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 52 65 61 64 49 6e 74 31 36 }
		$artifact3 = { 65 6e 76 3a 57 49 4e 44 49 52 5c 73 79 73 77 6f 77 36 34 5c 77 69 6e 64 6f 77 73 70 6f 77 65 72 73 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 22 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 65 78 65 63 20 62 79 70 61 73 73}
		$artifact4 = { 65 6e 76 3a 57 49 4e 44 49 52 5c 73 79 73 77 6f 77 36 34 5c 77 69 6e 64 6f 77 73 70 6f 77 65 72 73 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 22 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 66 69 6c 65}
		$artifact5 = {5b 50 61 72 61 6d 65 74 65 72 28 50 6f 73 69 74 69 6f 6e 20 3d 20 30 20 2c 20 4d 61 6e 64 61 74 6f 72 79}
		$artifact6 = {5b 50 61 72 61 6d 65 74 65 72 28 50 6f 73 69 74 69 6f 6e 20 3d 20 31 20 2c 20 4d 61 6e 64 61 74 6f 72 79}
		$artifact7 = {2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 50 61 73 73 20 2d 4e 6f 4c 6f 67 6f 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 4e 6f 45 78 69 74}
		$artifact8 = {72 65 74 75 72 6e 20 5b 42 69 74 43 6f 6e 76 65 72 74 65 72 5d 3a 3a 54 6f 49 6e 74 36 34}

	condition:
		6 of ($api*) or ((3 of ($artifact*)))
}
