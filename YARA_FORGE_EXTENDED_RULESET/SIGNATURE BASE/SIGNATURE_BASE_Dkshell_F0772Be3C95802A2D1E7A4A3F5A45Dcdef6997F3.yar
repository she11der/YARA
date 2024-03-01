rule SIGNATURE_BASE_Dkshell_F0772Be3C95802A2D1E7A4A3F5A45Dcdef6997F3 : FILE
{
	meta:
		description = "Detects a web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "161ceca6-f5e8-5bcf-bc31-2a2169b1a1c7"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9524-L9538"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "81b0a08d1b9d3640e656a5cd08b79c0a2f940a2db5c2d939d19509f993514e86"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7ea49d5c29f1242f81f2393b514798ff7caccb50d46c60bdfcf61db00043473b"

	strings:
		$s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
		$s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii

	condition:
		( uint16(0)==0x3c0a and filesize <300KB and all of them )
}
