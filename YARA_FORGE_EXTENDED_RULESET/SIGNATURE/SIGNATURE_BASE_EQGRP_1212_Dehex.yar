import "pe"

rule SIGNATURE_BASE_EQGRP_1212_Dehex : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - from files 1212.pl, dehex.pl"
		author = "Florian Roth (Nextron Systems)"
		id = "2cc375e6-2bff-5623-b86c-a6413f736c42"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L209-L226"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "74d1b0e820696cd5507996996bead50d283e83095bc7288a6e8e484738b6348b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "return \"ERROR:$line is not a valid address\";" fullword ascii
		$s2 = "print \"ERROR: the filename or hex representation needs to be one argument try using \\\"'s\\n\";" fullword ascii
		$s3 = "push(@octets,$byte_table{$tempi});" fullword ascii
		$s4 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
		$s5 = "print hextoIP($ARGV[0]);" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <6KB and (5 of ($s*))) or ( all of them )
}
