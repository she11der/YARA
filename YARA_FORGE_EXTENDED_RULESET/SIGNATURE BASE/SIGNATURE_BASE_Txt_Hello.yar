rule SIGNATURE_BASE_Txt_Hello : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file hello.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "42d01411-e333-543d-84a2-758c13bad2df"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L701-L717"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "697a9ebcea6a22a16ce1a51437fcb4e1a1d7f079"
		logic_hash = "823a0a74b07c8f4821247b3cf0450069a9888d44ccd87144330da88594f260c0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
		$s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
		$s2 = "myProcess.Start()" fullword ascii
		$s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii

	condition:
		filesize <25KB and all of them
}
