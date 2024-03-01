import "pe"

rule SIGNATURE_BASE_EQGRP_1212 : FILE
{
	meta:
		description = "Detects tool from EQGRP toolset - file 1212.pl"
		author = "Florian Roth (Nextron Systems)"
		id = "428fed4f-df5c-5fc2-ac4b-4dea69ea4f2d"
		date = "2016-08-15"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L189-L207"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1be7ed8fdfaecc6e55c4d1e75cf841f4620df3d2abe6aed2761aed20c42f70bd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
		$s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
		$s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
		$s4 = "$dstport=hextoPort($dstport);" fullword ascii
		$s5 = "sub hextoPort" fullword ascii
		$s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii

	condition:
		filesize <6KB and 4 of them
}
