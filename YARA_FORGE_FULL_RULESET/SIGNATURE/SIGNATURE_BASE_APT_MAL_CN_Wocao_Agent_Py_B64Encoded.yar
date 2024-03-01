rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Agent_Py_B64Encoded
{
	meta:
		description = "Piece of Base64 encoded data from Agent Python version"
		author = "Fox-IT SRT"
		id = "eb2701e9-4358-5d24-bfcd-b4dde24f13bf"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_wocao.yar#L77-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "279fb27637d9b62b484283f778215d042de9fb83110a233e048452e921c540ee"
		score = 75
		quality = 85
		tags = ""

	strings:
		$header = "QlpoOTFBWSZTWWDdHjgABDTfgHwQe////z/v/9+////6YA4cGPsAl2e8M9LSU128"

	condition:
		all of them
}
