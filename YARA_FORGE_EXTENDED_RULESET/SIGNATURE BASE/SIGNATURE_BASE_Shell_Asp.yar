rule SIGNATURE_BASE_Shell_Asp : FILE
{
	meta:
		description = "Chinese Hacktool Set Webshells - file Asp.html"
		author = "Florian Roth (Nextron Systems)"
		id = "52089205-8f36-5a0b-a1ae-67c91a253ad2"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L410-L425"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5e0bc914ac287aa1418f6554ddbe0ce25f2b5f20"
		logic_hash = "47c5c242713446471d5da4d9245b99561c26ad7fa016059076a6f0acab542c3c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
		$s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
		$s3 = "function Command(cmd, str){" fullword ascii

	condition:
		filesize <100KB and all of them
}
