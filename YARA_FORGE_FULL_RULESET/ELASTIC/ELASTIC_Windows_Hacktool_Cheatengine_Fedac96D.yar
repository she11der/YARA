rule ELASTIC_Windows_Hacktool_Cheatengine_Fedac96D : FILE
{
	meta:
		description = "Subject: Cheat Engine"
		author = "Elastic Security"
		id = "fedac96d-4c23-4c8d-8476-4c89fd610441"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Hacktool_CheatEngine.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "b20b339a7b61dc7dbc9a36c45492ba9654a8b8a7c8cbc202ed1dfed427cfd799"
		logic_hash = "426b6d388f86dd935d8165af0fb7c8491c987542755ec4c7c53a35a9003f8680"
		score = 75
		quality = 35
		tags = "FILE"
		fingerprint = "94d375ddab90c27ef22dd18b98952d0ec8a4d911151970d5b9f59654a8e3d7db"
		threat_name = "Windows.Hacktool.CheatEngine"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 43 68 65 61 74 20 45 6E 67 69 6E 65 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}
