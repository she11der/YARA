rule ELASTIC_Windows_Trojan_Icedid_48029E37 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "48029e37-b392-4d53-b0de-2079f6a8a9d9"
		date = "2022-04-06"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/yara/rules/Windows_Trojan_IcedID.yar#L178-L196"
		license_url = "https://github.com/elastic/protections-artifacts//blob/8b6b3b3977b462ae1c68ae8756c095b6bcba2da6/LICENSE.txt"
		hash = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
		logic_hash = "1fe337d7a0607938aaf57cf25c1373aadf315b7a8cec133d6d30a38bd58e1027"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "375266b526fe14354550d000d3a10dde3f6a85e11f4ba5cab14d9e1f878de51e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 C1 E3 10 0F 31 48 C1 E2 ?? 48 0B C2 0F B7 C8 48 0B D9 8B CB 83 E1 }

	condition:
		all of them
}
