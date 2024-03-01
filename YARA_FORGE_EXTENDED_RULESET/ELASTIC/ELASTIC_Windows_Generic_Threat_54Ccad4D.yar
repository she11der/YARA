rule ELASTIC_Windows_Generic_Threat_54Ccad4D : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "54ccad4d-3b8d-4abb-88eb-d428d661169d"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Generic_Threat.yar#L1402-L1422"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "fe4aad002722d2173dd661b7b34cdb0e3d4d8cd600e4165975c48bf1b135763f"
		logic_hash = "b9fb525be22dd2f235c3ac68688ced5298da45194ad032423689f5a085df6e31"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "4fe13c4ca3569912978a0c2231ec53a715a314e1158e09bc0c61f18151cfffa3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 4D 55 73 65 72 4E 61 74 69 66 65 72 63 }
		$a2 = { 4D 79 52 65 67 53 61 76 65 52 65 63 6F 72 64 }
		$a3 = { 53 74 65 61 6C 65 72 54 69 6D 65 4F 75 74 }

	condition:
		all of them
}
