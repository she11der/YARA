rule TRELLIX_ARC_Apt_Nix_Elf_Derusbi_Linux_Strings : BACKDOOR FILE
{
	meta:
		description = "Rule to detect APT Derusbi Linux Strings"
		author = "Marc Rivero | McAfee ATR Team"
		id = "09e47580-9b20-5461-943e-32b932c36214"
		date = "2017-05-31"
		modified = "2020-08-14"
		reference = "https://attack.mitre.org/software/S0021/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_Derusbi.yar#L132-L173"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "0e95497c44a0c1d85936a6a072063720a771b7e1eb8da2377e54577e3fc2764e"
		score = 75
		quality = 68
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:ELF/Derusbi"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$a1 = "loadso" wide ascii fullword
		$a2 = "\nuname -a\n\n" wide ascii
		$a3 = "/dev/shm/.x11.id" wide ascii
		$a4 = "LxMain64" wide ascii nocase
		$a5 = "# \\u@\\h:\\w \\$ " wide ascii
		$b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
		$b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
		$b3 = "ret %d" wide fullword
		$b4 = "uname -a\n\n" wide ascii
		$b5 = "/proc/%u/cmdline" wide ascii
		$b6 = "/proc/self/exe" wide ascii
		$b7 = "cp -a %s %s" wide ascii
		$c1 = "/dev/pts/4" wide ascii fullword
		$c2 = "/tmp/1408.log" wide ascii fullword

	condition:
		uint32(0)==0x464C457F and filesize <200KB and ((1 of ($a*) and 4 of ($b*)) or (1 of ($a*) and 1 of ($c*)) or 2 of ($a*) or all of ($b*))
}
