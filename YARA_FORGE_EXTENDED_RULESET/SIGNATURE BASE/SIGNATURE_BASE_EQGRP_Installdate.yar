import "pe"

rule SIGNATURE_BASE_EQGRP_Installdate : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file installdate.pl"
		author = "Florian Roth (Nextron Systems)"
		id = "029b1213-1206-5b7c-bd72-93239a23fe8a"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L31-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "363a9c92c4d2560ba6dd0ec41acf136dff4346f20d54f971d319ed2aa531fe31"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "#Provide hex or EP log as command-line argument or as input" fullword ascii
		$x2 = "print \"Gimme hex: \";" fullword ascii
		$x3 = "if ($line =~ /Reg_Dword:  (\\d\\d:\\d\\d:\\d\\d.\\d+ \\d+ - )?(\\S*)/) {" fullword ascii
		$s1 = "if ($_ =~ /InstallDate/) {" fullword ascii
		$s2 = "if (not($cmdInput)) {" fullword ascii
		$s3 = "print \"$hex in decimal=$dec\\n\\n\";" fullword ascii

	condition:
		filesize <2KB and (1 of ($x*) or 3 of them )
}
