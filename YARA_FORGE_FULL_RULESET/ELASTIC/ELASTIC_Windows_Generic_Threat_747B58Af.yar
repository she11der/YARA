rule ELASTIC_Windows_Generic_Threat_747B58Af : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "747b58af-6edb-42f2-8a1b-e462399ef61e"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Generic_Threat.yar#L1504-L1524"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "ee28e93412c59d63155fd79bc99979a5664c48dcb3c77e121d17fa985fcb0ebe"
		logic_hash = "fd6b36ca50c1017035474b491f716bfb0d53b181fce4b5478a57a1d1a6ddc3e7"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "79faab4fda6609b2c95d24de92a3a417d2f5e58f3f83c856fa9f32e80bed6f37"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 5C 43 3D 5D 78 48 73 66 40 22 33 2D 34 }
		$a2 = { 79 5A 4E 51 61 4A 21 43 43 56 31 37 74 6B }
		$a3 = { 66 72 7A 64 48 49 2D 4E 3A 4D 23 43 }

	condition:
		all of them
}
