rule SIGNATURE_BASE_Pw_Inspector_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "795c7009-93a8-57c4-8554-f0ed5c1d50f8"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1508-L1524"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e0a1117ee4a29bb4cf43e3a80fb9eaa63bb377bf"
		logic_hash = "7d2021ff471f03deb9e6d8b62fcb218ae3198f21fd7b8fa1fdd9b96228b8c2f8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
		$s2 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
		$s3 = "PW-Inspector" fullword ascii
		$s4 = "i:o:m:M:c:lunps" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 2 of them
}
