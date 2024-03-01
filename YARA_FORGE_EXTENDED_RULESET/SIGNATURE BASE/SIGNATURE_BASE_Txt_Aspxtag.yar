rule SIGNATURE_BASE_Txt_Aspxtag : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L428-L443"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "42cb272c02dbd49856816d903833d423d3759948"
		logic_hash = "6ffeee18945cab96673e4b9efc143017d168be12b794fa26aa4a304f15ae8e13"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "String wGetUrl=Request.QueryString[" fullword ascii
		$s2 = "sw.Write(wget);" fullword ascii
		$s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii

	condition:
		filesize <2KB and all of them
}
