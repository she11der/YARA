rule ELASTIC_Windows_Generic_Threat_B1F6F662 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "b1f6f662-ea77-4049-a58a-ed8a97d7738e"
		date = "2024-01-01"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Generic_Threat.yar#L403-L423"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "1b7eaef3cf1bb8021a00df092c829932cccac333990db1c5dac6558a5d906400"
		logic_hash = "e52ff1eaee00334e1a07367bf88f3907bb0b13035717683d9d98371b92bc45c0"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "f2cd22e34b4694f707ee9042805f5498ce66d35743950096271aaa170f44a2ee"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
		$a2 = { 73 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
		$a3 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 31 }

	condition:
		all of them
}
