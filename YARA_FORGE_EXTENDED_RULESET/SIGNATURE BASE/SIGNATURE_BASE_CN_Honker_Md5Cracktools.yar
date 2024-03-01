rule SIGNATURE_BASE_CN_Honker_Md5Cracktools : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Md5CrackTools.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "16e04a66-0f6f-5b94-97c3-df62aa9406a9"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L155-L170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "9dfd9c9923ae6f6fe4cbfa9eb69688269285939c"
		logic_hash = "a176393c0324bcc634a31c261aa6b528fb5a5893c40a5534b34253a1922c8285"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s2 = ",<a href='index.php?c=1&type=md5&hash=" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <4580KB and all of them
}
