rule ELASTIC_Windows_Generic_Threat_2Bb6F41D : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "2bb6f41d-41bb-4257-84ef-9026fcc0ebec"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Generic_Threat.yar#L1708-L1728"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "afa060352346dda4807dffbcac75bf07e8800d87ff72971b65e9805fabef39c0"
		logic_hash = "7c4e62b69880eb8a901d7e94b7539786e8ac58808df07cb1cbe9ff45efce518e"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "d9062e792a0b8f92a03c0fdadd4dd651a0072faa3dd439bb31399a0c75a78c21"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 67 65 74 5F 73 45 78 70 59 65 61 72 }
		$a2 = { 73 65 74 5F 73 45 78 70 59 65 61 72 }
		$a3 = { 42 72 6F 77 73 65 72 50 61 74 68 54 6F 41 70 70 4E 61 6D 65 }

	condition:
		all of them
}
