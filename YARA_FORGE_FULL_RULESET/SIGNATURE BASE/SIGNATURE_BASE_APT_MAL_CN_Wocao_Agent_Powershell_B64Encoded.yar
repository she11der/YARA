rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Agent_Powershell_B64Encoded
{
	meta:
		description = "Piece of Base64 encoded data from Agent CSharp version"
		author = "Fox-IT SRT"
		id = "14e1702d-6229-5989-8bb7-cc9c0c321676"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_wocao.yar#L40-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bcf9a75dbbf90044db76c56ffd07971d4252b0e75d73abf402ca4fadbfb59767"
		score = 75
		quality = 85
		tags = ""

	strings:
		$header = "LFNVT0hBBnVfVVJDSx0sU1VPSEEGdV9VUkNLCG9pHSxTVU9IQQZ1X1VSQ0sIZUlK"

	condition:
		all of them
}
