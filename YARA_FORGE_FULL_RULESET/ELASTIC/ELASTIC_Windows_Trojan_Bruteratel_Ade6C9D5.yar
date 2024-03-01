rule ELASTIC_Windows_Trojan_Bruteratel_Ade6C9D5 : FILE MEMORY
{
	meta:
		description = "Targets API hashes used by BruteRatel"
		author = "Elastic Security"
		id = "ade6c9d5-e9b5-4ef8-bacd-2f050c25f7f6"
		date = "2023-01-24"
		modified = "2023-02-01"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_BruteRatel.yar#L86-L109"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "dc9757c9aa3aff76d86f9f23a3d20a817e48ca3d7294307cc67477177af5c0d4"
		logic_hash = "8ff8ed1e2b909606fe6aae3f43ad02898d7b3906c3d329a508f6d40490ec75a0"
		score = 60
		quality = 45
		tags = "FILE, MEMORY"
		fingerprint = "9a4c5660eeb9158652561cf120e91ea5887841ed71f69e7cf4bfe4cfb11fe74a"
		threat_name = "Windows.Trojan.BruteRatel"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1_NtReadVirtualMemory = { AA A5 EF 3A }
		$c2_NtQuerySystemInformation = { D6 CA E1 E4 }
		$c3_NtCreateFile = { 9D 8F 88 03 }
		$c4_RtlSetCurrentTranscation = { 90 85 A3 99 }
		$c5_LoadLibrary = { 8E 4E 0E EC }

	condition:
		all of them
}
