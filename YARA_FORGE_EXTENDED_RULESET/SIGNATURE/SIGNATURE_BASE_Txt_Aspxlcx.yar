rule SIGNATURE_BASE_Txt_Aspxlcx : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L628-L644"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "453dd3160db17d0d762e032818a5a10baf234e03"
		logic_hash = "a6e41e6882e74b0dd55ec4afbf6f8708e28267657e304c97d1304266fe1fbc93"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "public string remoteip = " ascii
		$s2 = "=Dns.Resolve(host);" ascii
		$s3 = "public string remoteport = " ascii
		$s4 = "public class PortForward" ascii

	condition:
		uint16(0)==0x253c and filesize <18KB and all of them
}
