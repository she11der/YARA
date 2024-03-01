rule ELASTIC_Windows_Trojan_Smokeloader_3687686F : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Smokeloader (Windows.Trojan.Smokeloader)"
		author = "Elastic Security"
		id = "3687686f-8fbf-4f09-9afa-612ee65dc86c"
		date = "2021-07-21"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Trojan_Smokeloader.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "8b3014ecd962a335b246f6c70fc820247e8bdaef98136e464b1fdb824031eef7"
		logic_hash = "d6c8b1d8c64b07cea2329ef111b3e51605c1cd5d2c525db89bc1f892149383fe"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0f483f9f79ae29b944825c1987366d7b450312f475845e2242a07674580918bc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }

	condition:
		all of them
}
