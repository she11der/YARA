rule SIGNATURE_BASE_Cookietools2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f227ba4b-9cad-5aac-99ab-46a8237249d4"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1717-L1733"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"
		logic_hash = "8ddb8ea0bc047877d91f25375745ab8fa66af28b6b41de36e0fb16ea8284fce5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "www.gxgl.com&www.gxgl.net" fullword wide
		$s2 = "ip.asp?IP=" fullword ascii
		$s3 = "MSIE 5.5;" fullword ascii
		$s4 = "SOFTWARE\\Borland\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
