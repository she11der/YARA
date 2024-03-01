rule ELASTIC_Linux_Backdoor_Fontonlake_Fe916A45 : FILE MEMORY
{
	meta:
		description = "Detects Linux Backdoor Fontonlake (Linux.Backdoor.Fontonlake)"
		author = "Elastic Security"
		id = "fe916a45-75cc-40e4-94ad-6ac0f5d815b9"
		date = "2021-10-12"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/yara/rules/Linux_Backdoor_Fontonlake.yar#L1-L29"
		license_url = "https://github.com/elastic/protections-artifacts//blob/6d54ae289b290b1d42a7717569483f6ce907200a/LICENSE.txt"
		hash = "8a0a9740cf928b3bd1157a9044c6aced0dfeef3aa25e9ff9c93e113cbc1117ee"
		logic_hash = "590b28264345ea0bdbd53791f422cb4f1fad143df2b790824fc182356a568d7d"
		score = 75
		quality = 48
		tags = "FILE, MEMORY"
		fingerprint = "85f16dd4a127737501863ccba006a444d899c6edc6ab03af5dddef2d39edc483"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = ".cmd.Upload_Passwd.PasswordInfo" fullword
		$a2 = "Upload_Passwd" fullword
		$a3 = "upload_file_beg" fullword
		$a4 = "upload_file_ing" fullword
		$a5 = "upload_file_end" fullword
		$a6 = "modify_file_attr" fullword
		$a7 = "modify_file_time" fullword
		$a8 = "import platform;print(platform.linux_distribution()[0]);print(platform.linux_distribution()[1]);print(platform.release())" fullword
		$a9 = "inject.so" fullword
		$a10 = "rm -f /tmp/%s" fullword
		$a11 = "/proc/.dot3" fullword

	condition:
		4 of them
}
