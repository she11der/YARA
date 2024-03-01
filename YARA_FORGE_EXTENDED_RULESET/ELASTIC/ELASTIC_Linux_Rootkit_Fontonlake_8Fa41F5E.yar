rule ELASTIC_Linux_Rootkit_Fontonlake_8Fa41F5E : FILE MEMORY
{
	meta:
		description = "Detects Linux Rootkit Fontonlake (Linux.Rootkit.Fontonlake)"
		author = "Elastic Security"
		id = "8fa41f5e-d03d-4647-86fb-335e056c1c0d"
		date = "2021-10-12"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Linux_Rootkit_Fontonlake.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		hash = "826222d399e2fb17ae6bc6a4e1493003881b1406154c4b817f0216249d04a234"
		logic_hash = "e90ace26dd74ae948d2469c6f532af5ec3070a21092f8b2c4d47c4f5b9d04c09"
		score = 75
		quality = 50
		tags = "FILE, MEMORY"
		fingerprint = "187aae8e659061a06b44e0d353e35e22ada9076c78d8a7e4493e1e4cc600bc9d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "kernel_write" fullword
		$a2 = "/proc/.dot3" fullword
		$a3 = "hide_pid" fullword
		$h2 = "s_hide_pids" fullword
		$h3 = "s_hide_tcp4_ports" fullword
		$h4 = "s_hide_strs" fullword
		$tmp1 = "/tmp/.tmH" fullword
		$tmp2 = "/tmp/.tmp_" fullword

	condition:
		( all of ($a*) and 1 of ($tmp*)) or ( all of ($h*))
}
