rule SIGNATURE_BASE_Txt_Aspx1 : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L463-L477"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
		logic_hash = "20bdadd6c8b61ab14f6280f55a90f541bf65c33675f979ebe489cc3967438e15"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
		$s1 = "],\"unsafe\");%>" fullword ascii

	condition:
		filesize <150 and all of them
}
