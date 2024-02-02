rule ELASTIC_Windows_Trojan_Agenttesla_Ebf431A8___FILE_MEMORY
{
	meta:
		description = "Detects Windows Trojan Agenttesla (Windows.Trojan.AgentTesla)"
		author = "Elastic Security"
		id = "ebf431a8-45e8-416c-a355-4ac1db2d133a"
		date = "2023-12-01"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Windows_Trojan_AgentTesla.yar#L120-L143"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		hash = "0cb3051a80a0515ce715b71fdf64abebfb8c71b9814903cb9abcf16c0403f62b"
		logic_hash = "b02d6e2d68b336aaa37336e0c0c3ffa6c7a126bfcdb6cb6ad5a3432004c6030c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2d95dbe502421d862eee33ba819b41cb39cf77a44289f4de4a506cad22f3fddb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "MozillaBrowserList"
		$a2 = "EnableScreenLogger"
		$a3 = "VaultGetItem_WIN7"
		$a4 = "PublicIpAddressGrab"
		$a5 = "EnableTorPanel"
		$a6 = "get_GuidMasterKey"

	condition:
		4 of them
}