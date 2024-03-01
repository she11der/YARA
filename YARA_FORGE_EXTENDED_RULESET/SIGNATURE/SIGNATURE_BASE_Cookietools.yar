rule SIGNATURE_BASE_Cookietools : FILE
{
	meta:
		description = "Chinese Hacktool Set - file CookieTools.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "893884e5-6f4c-5f67-9382-8bf1ee45a257"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L277-L294"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"
		logic_hash = "7f8c59ef58a92db15d8965e54ed6e26834e268581581af2a0ff98a6f46564e7e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
		$s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s8 = "OnGetPasswordP" fullword ascii
		$s12 = "http://www.chinesehack.org/" ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and 4 of them
}
