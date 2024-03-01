rule ELASTIC_Linux_Ransomware_Lockbit_5B30A04B : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Lockbit (Linux.Ransomware.Lockbit)"
		author = "Elastic Security"
		id = "5b30a04b-d618-4698-a797-30bf6d4a001c"
		date = "2023-07-29"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Ransomware_Lockbit.yar#L26-L46"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "41cbb7d79388eaa4d6e704bd4a8bf8f34d486d27277001c343ea3ce112f4fb0d"
		logic_hash = "b89d0f25f08ffa35e075def6a29cf52a80500c6499732146426a71c741059a3b"
		score = 75
		quality = 69
		tags = "FILE, MEMORY"
		fingerprint = "99bf6afb1554ec3b3b82389c93ca87018c51f7a80270d64007a5f5fc59715c45"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 5D 50 4A 49 55 58 40 77 58 54 5C }
		$a2 = { 33 6B 5C 5A 4C 4B 4A 50 4F 5C 55 40 }
		$a3 = { 5E 4C 58 4B 58 57 4D 5C 5C 5D }

	condition:
		all of them
}
