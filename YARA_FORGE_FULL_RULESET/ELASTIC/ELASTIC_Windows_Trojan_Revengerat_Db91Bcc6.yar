rule ELASTIC_Windows_Trojan_Revengerat_Db91Bcc6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Revengerat (Windows.Trojan.Revengerat)"
		author = "Elastic Security"
		id = "db91bcc6-024d-42da-8d0a-bd69374bf622"
		date = "2021-09-02"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Windows_Trojan_Revengerat.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "30d8f81a19976d67b495eb1324372598cc25e1e69179c11efa22025341e455bd"
		logic_hash = "1e33cb1d614aae0b2181ebaca694c69e7fc849b3a3b7ffff7059e8c43553f8cc"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "9c322655f50c32b9be23accd2b38fbda43c280284fbf05a5a5c98458c2bab666"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Revenge-RAT" wide fullword
		$a2 = "SELECT * FROM FirewallProduct" wide fullword
		$a3 = "HKEY_CURRENT_USER\\SOFTWARE\\" wide fullword
		$a4 = "get_MachineName" ascii fullword

	condition:
		all of them
}
