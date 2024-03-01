rule ELASTIC_Linux_Ransomware_Redalert_39642D52 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Redalert (Linux.Ransomware.RedAlert)"
		author = "Elastic Security"
		id = "39642d52-0a4b-48d5-bb62-8f37beb4dc6a"
		date = "2022-07-06"
		modified = "2022-08-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Ransomware_RedAlert.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
		logic_hash = "fa8fc16f0c8a55dd78781d334d7f55db6aa5e60f76cebf5282150af8ceb08dc3"
		score = 75
		quality = 48
		tags = "FILE, MEMORY"
		fingerprint = "744524ee2ae9e3e232f15b0576cdab836ac0fe3c9925eab66ed8c6b0be3f23d7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$str_ransomnote = "\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\% REDALERT UNIQUE IDENTIFIER START \\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%" ascii fullword
		$str_print = "\t\t\t########\n\t\t\t[ N13V ]\n\t\t\t########\n\n" ascii fullword
		$str_arg = "[info] Catch -t argument. Check encryption time" ascii fullword
		$str_ext = ".crypt658" ascii fullword
		$byte_checkvm = { 48 8B 14 DD ?? ?? ?? ?? 31 C0 48 83 C9 FF FC 48 89 EE 48 89 D7 F2 AE 4C 89 E7 48 F7 D1 E8 }

	condition:
		3 of ($str_*) or ($byte_checkvm and $str_print)
}
