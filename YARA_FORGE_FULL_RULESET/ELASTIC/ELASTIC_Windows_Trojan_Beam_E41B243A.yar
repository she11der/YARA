rule ELASTIC_Windows_Trojan_Beam_E41B243A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Beam (Windows.Trojan.Beam)"
		author = "Elastic Security"
		id = "e41b243a-020f-485e-b4bc-4db9d593e7af"
		date = "2021-12-07"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Beam.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "233a1f1dcbb679d31dab7744358b434cccabfc752baf53ba991388ced098f7c8"
		logic_hash = "295837743ecfa51e1713d19cba24ff8885c8716201caac058ae8b2bc9e008e6c"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "0863f858fcc03d9b5994e73ee3b9daf64b57b0eecd67b718eafa2ed162cf7878"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 69 70 22 3A 22 28 5B 30 2D 39 2E 5D 2B 29 }
		$a2 = { 63 6F 75 6E 74 72 79 5F 63 6F 64 65 22 3A 22 28 5C 77 2A 29 }
		$a3 = { 20 2F 66 20 26 20 65 72 61 73 65 20 }
		$a4 = "\\BeamWinHTTP2\\Release\\BeamWinHTTP.pdb"

	condition:
		all of them
}
