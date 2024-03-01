rule ELASTIC_Windows_Generic_Threat_Ab01Ba9E : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "ab01ba9e-01e6-405b-8aaf-ae06a8fe2454"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Generic_Threat.yar#L1809-L1829"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "2b237716d0c0c9877f54b3fa03823068728dfe0710c5b05e9808eab365a1408e"
		logic_hash = "cc8d79950e21270938d2ea7e501c7c8fdbebe92767b48b46bb03c08c377e095b"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "dd9feb5d5756b3d3551ae21982b5e6eb189576298697b7d7d4bd042e4fc4c74f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 53 3C 3B 54 24 38 74 23 45 3B 6C 24 2C }
		$a2 = { 3A 3D 3B 47 3B 55 3B 63 3B 6A 3B 7A 3B }
		$a3 = { 56 30 61 30 6B 30 77 30 7C 30 24 39 32 39 37 39 41 39 4F 39 5D 39 64 39 75 39 }

	condition:
		all of them
}
