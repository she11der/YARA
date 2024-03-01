rule SIGNATURE_BASE_F3_Diy : FILE
{
	meta:
		description = "Chinese Hacktool Set - file diy.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "9f36c6dd-89e8-511b-a499-131f1e8a420a"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L293-L307"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"
		logic_hash = "37d6bc61d790ff30c98ded08ff875431fda525cd3ac10b4b1ba3f8f42167ed8c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
		$s5 = ".black {" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <10KB and all of them
}
