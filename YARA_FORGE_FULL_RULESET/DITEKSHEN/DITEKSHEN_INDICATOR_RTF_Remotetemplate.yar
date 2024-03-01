rule DITEKSHEN_INDICATOR_RTF_Remotetemplate : CVE_2017_11882 FILE
{
	meta:
		description = "Detects RTF documents potentially exploiting CVE-2017-11882"
		author = "ditekSHen"
		id = "59b31243-a360-531f-99ea-32b54d19ab52"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_office.yar#L918-L928"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3a75072bc4d9c7dc53220afe359911c04cd3267c142058352de80ec430a53517"
		score = 60
		quality = 35
		tags = "CVE-2017-11882, FILE"

	strings:
		$s1 = "{\\*\\template http" ascii nocase
		$s2 = "{\\*\\template file" ascii nocase
		$s3 = "{\\*\\template \\u-" ascii nocase

	condition:
		uint32(0)==0x74725c7b and 1 of them
}
