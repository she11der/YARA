import "pe"

rule SIGNATURE_BASE_EQGRP_Workit
{
	meta:
		description = "EQGRP Toolset Firewall - file workit.py"
		author = "Florian Roth (Nextron Systems)"
		id = "b582f990-5bd5-592d-a7c0-475fdfffc38c"
		date = "2016-08-16"
		modified = "2023-01-27"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L542-L566"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1fa61e8c2012e664fee97ff608bcd8845bbd9701fa02d39d49379f7f83a5636d"
		score = 75
		quality = 35
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"

	strings:
		$s1 = "macdef init > /tmp/.netrc;" fullword ascii
		$s2 = "/usr/bin/wget http://" ascii
		$s3 = "HOME=/tmp ftp" fullword ascii
		$s4 = " >> /tmp/.netrc;" fullword ascii
		$s5 = "/usr/rapidstream/bin/tftp" fullword ascii
		$s6 = "created shell_command:" fullword ascii
		$s7 = "rm -f /tmp/.netrc;" fullword ascii
		$s8 = "echo quit >> /tmp/.netrc;" fullword ascii
		$s9 = "echo binary >> /tmp/.netrc;" fullword ascii
		$s10 = "chmod 600 /tmp/.netrc;" fullword ascii
		$s11 = "created cli_command:" fullword ascii

	condition:
		6 of them
}
