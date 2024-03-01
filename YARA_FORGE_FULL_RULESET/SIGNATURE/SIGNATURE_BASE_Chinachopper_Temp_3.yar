rule SIGNATURE_BASE_Chinachopper_Temp_3 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file temp.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "573e7da6-f58f-5814-b3e8-a0db3ecfe558"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L394-L408"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
		logic_hash = "6a0d7817607362f325957e30cace24d32635b7e0411e161588ee573118f91b6a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
		$s1 = "\"],\"unsafe\");%>" ascii

	condition:
		uint16(0)==0x253c and filesize <150 and all of them
}
