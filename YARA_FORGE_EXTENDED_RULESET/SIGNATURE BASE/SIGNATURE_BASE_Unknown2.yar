rule SIGNATURE_BASE_Unknown2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file unknown2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "af7ddcbf-1cba-51a9-b435-9a267320f502"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2109-L2128"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"
		logic_hash = "dea499eaa87cc454a31672fb842539779926d50785ef827162fde84bfcdcc54a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" wide
		$s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" wide
		$s3 = "http://www.md5.com.cn" fullword wide
		$s4 = "1.5.exe" fullword wide
		$s5 = "\\Set.ini" wide
		$s6 = "OpenFileDialog1" fullword wide
		$s7 = " (*.txt)|*.txt" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 4 of them
}
