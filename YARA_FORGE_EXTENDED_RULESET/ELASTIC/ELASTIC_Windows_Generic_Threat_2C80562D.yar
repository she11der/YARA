rule ELASTIC_Windows_Generic_Threat_2C80562D : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "2c80562d-2377-43b2-864f-0f122530b85d"
		date = "2024-01-01"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Generic_Threat.yar#L425-L445"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "ee8decf1e8e5a927e3a6c10e88093bb4b7708c3fd542d98d43f1a882c6b0198e"
		logic_hash = "07487ae646ac81b94f940c8d3493dbee023bce687297465fe09375f40dff0fb2"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "30965c0d6ac30cfb10674b2600e5a1e7b14380072738dd7993bd3eb57c825f24"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 50 6F 6C 79 6D 6F 64 58 54 2E 65 78 65 }
		$a2 = { 50 6F 6C 79 6D 6F 64 58 54 20 76 31 2E 33 }
		$a3 = { 50 6F 6C 79 6D 6F 64 20 49 6E 63 2E }

	condition:
		all of them
}
