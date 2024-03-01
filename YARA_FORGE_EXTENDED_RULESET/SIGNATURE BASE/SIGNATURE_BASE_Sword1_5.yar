rule SIGNATURE_BASE_Sword1_5 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dff8666a-0373-5605-9012-92b2b3ec71ea"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1430-L1449"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
		logic_hash = "09e09f7ea16dc917388cbccb22a7abfed9b693a33d61698f0e838f029402c256"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "http://www.ip138.com/ip2city.asp" fullword wide
		$s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s6 = "ListBox_Command" fullword wide
		$s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
		$s18 = "\\Set.ini" wide
		$s19 = "OpenFileDialog1" fullword wide
		$s20 = " (*.txt)|*.txt" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 4 of them
}
