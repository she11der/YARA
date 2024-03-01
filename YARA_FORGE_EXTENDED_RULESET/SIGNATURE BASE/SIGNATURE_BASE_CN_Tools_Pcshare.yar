rule SIGNATURE_BASE_CN_Tools_Pcshare : FILE
{
	meta:
		description = "Chinese Hacktool Set - file PcShare.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0c4e9f9b-9839-56a0-be21-a4e9f19cdfdb"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L546-L565"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ee7ba9784fae413d644cdf5a093bd93b73537652"
		logic_hash = "57bd1629abe0af1345f505514b99deb4e63ebce7363f3b0abcb76e7201d9b7b7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "title=%s%s-%s;id=%s;hwnd=%d;mainhwnd=%d;mainprocess=%d;cmd=%d;" fullword wide
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
		$s2 = "http://www.pcshares.cn/pcshare200/lostpass.asp" fullword wide
		$s5 = "port=%s;name=%s;pass=%s;" fullword wide
		$s16 = "%s\\ini\\*.dat" fullword wide
		$s17 = "pcinit.exe" fullword wide
		$s18 = "http://www.pcshare.cn" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <6000KB and 3 of them
}
