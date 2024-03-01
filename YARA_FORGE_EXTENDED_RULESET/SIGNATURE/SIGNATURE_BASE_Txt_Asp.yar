rule SIGNATURE_BASE_Txt_Asp : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file asp.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "39a2ba9a-c429-574f-8820-5e0270a4b84c"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L498-L512"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a63549f749f4d9d0861825764e042e299e06a705"
		logic_hash = "9eab239310fbebe8c88cbf8d0ee4123b8f3e2ebe601949e1e984e9cfde9869e7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
		$s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <100KB and all of them
}
