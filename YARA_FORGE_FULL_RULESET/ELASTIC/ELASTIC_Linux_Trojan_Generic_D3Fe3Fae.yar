rule ELASTIC_Linux_Trojan_Generic_D3Fe3Fae : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "d3fe3fae-f7ec-48d5-8b17-9ab11a5b689f"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Trojan_Generic.yar#L201-L219"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "2a2542142adb05bff753e0652e119c1d49232d61c49134f13192425653332dc3"
		logic_hash = "0b980a0bcf8340410fe2b53d109f629c6e871ebe82af467153d7b50b73fd8644"
		score = 60
		quality = 43
		tags = "FILE, MEMORY"
		fingerprint = "1773a3e22cb44fe0b3e68d343a92939a955027e735c60b48cf3b7312ce3a6415"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 47 53 45 54 2C 20 70 69 64 2C 20 4E 54 5F 50 52 53 54 41 54 }

	condition:
		all of them
}
