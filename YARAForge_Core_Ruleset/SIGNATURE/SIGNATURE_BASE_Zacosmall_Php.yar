rule SIGNATURE_BASE_Zacosmall_Php
{
	meta:
		description = "Semi-Auto-generated  - file zacosmall.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "25946aa7-7c56-5670-ae2f-c55e65a3b911"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4118-L4130"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
		logic_hash = "5a2125fc447344f8cc708503d9e4dd82f9b873e40ded497ef9e01974d08bf043"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "rand(1,99999);$sj98"
		$s1 = "$dump_file.='`'.$rows2[0].'`"
		$s3 = "filename=\\\"dump_{$db_dump}_${table_d"

	condition:
		2 of them
}