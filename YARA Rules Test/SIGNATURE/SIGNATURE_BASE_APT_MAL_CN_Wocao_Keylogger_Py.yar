rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Keylogger_Py
{
	meta:
		description = "Strings from Python keylogger"
		author = "Fox-IT SRT"
		id = "f7b5ec1b-669e-5e7d-a9d3-011d212eb363"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L91-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "2dc2ce153d559d795f302f5ca4a9ef9e6e5c54762472e38e6f4a26ef8a28a184"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "c:\\windows\\temp\\tap.tmp"
		$b = "c:\\windows\\temp\\mrteeh.tmp"
		$c = "GenFileName"
		$d = "outfile"
		$e = "[PASTE:%d]"

	condition:
		3 of them
}