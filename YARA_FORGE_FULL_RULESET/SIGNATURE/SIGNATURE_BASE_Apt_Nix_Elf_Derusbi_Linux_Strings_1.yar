rule SIGNATURE_BASE_Apt_Nix_Elf_Derusbi_Linux_Strings_1 : FILE
{
	meta:
		description = "Detects Derusbi Backdoor ELF Strings"
		author = "Fidelis Cybersecurity"
		id = "06717cc9-678d-5912-a671-65605b9c9968"
		date = "2016-02-29"
		modified = "2023-12-05"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_turbo_campaign.yar#L98-L128"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b54b406a562247d4c3d4a9c4d1b7584bdcecfe5b6c76867c04770e016eeb8c9a"
		score = 75
		quality = 83
		tags = "FILE"

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
		uint32(0)==0x464C457F and ((1 of ($a*) and 4 of ($b*)) or (1 of ($a*) and 1 of ($c*)) or 2 of ($a*) or all of ($b*))
}
