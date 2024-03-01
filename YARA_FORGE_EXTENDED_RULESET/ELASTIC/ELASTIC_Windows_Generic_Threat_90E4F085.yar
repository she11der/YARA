rule ELASTIC_Windows_Generic_Threat_90E4F085 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "90e4f085-2f53-4e5e-bcb6-c24823539241"
		date = "2024-01-12"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Generic_Threat.yar#L1117-L1137"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "1a6a290d98f5957d00756fc55187c78030de7031544a981fd2bb4cfeae732168"
		logic_hash = "2afeae6de965ae155914dcedbfe375327a9fca3b42733c23360dd4fddfcc8a3d"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "1d40eef44166b3cc89b1f2ba9c667032fa44cba271db8b82cc2fed738225712a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 39 39 21 3A 37 3B 45 3C 50 3D 5B 3E 66 3F }
		$a2 = { 66 32 33 39 20 3A 4E 3D 72 68 74 76 48 }
		$a3 = { 32 78 37 7A 42 5A 4C 22 2A 66 49 7A 75 }

	condition:
		all of them
}
