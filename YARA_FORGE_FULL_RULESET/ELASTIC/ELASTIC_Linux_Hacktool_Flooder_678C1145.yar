rule ELASTIC_Linux_Hacktool_Flooder_678C1145 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "678c1145-cc41-4e83-bc88-30f64da46dd3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Hacktool_Flooder.yar#L200-L218"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "559793b9cb5340478f76aaf5f81c8dbfbcfa826657713d5257dac3c496b243a6"
		logic_hash = "5ff15c8d92bca62700bbb67aeebc41fd603687dbc0c93733955bf59375df40a1"
		score = 60
		quality = 45
		tags = "FILE, MEMORY"
		fingerprint = "f4f66668b45f520bc107b7f671f8c7f42073d7ff28863e846a74fbd6cac03e87"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C8 48 BA AB AA AA AA AA AA AA AA 48 89 C8 48 F7 E2 48 C1 EA 05 48 }

	condition:
		all of them
}
