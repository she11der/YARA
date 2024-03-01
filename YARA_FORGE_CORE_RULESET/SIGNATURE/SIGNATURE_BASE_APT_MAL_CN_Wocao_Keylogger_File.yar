rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Keylogger_File
{
	meta:
		description = "Rule for finding keylogger output files"
		author = "Fox-IT SRT"
		id = "22e866b3-4b02-593a-b9a6-aa86870b6509"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L109-L121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6d2d677b69eaf31843e8352bfe040c9e5a8d423d17900e022b769d28789f2d98"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = { 0d 0a 20 [3-10] 53 74 61 72 74 75 70 3a 20 [3] 20 [3] 20 [2] 20 [2] 3a [2] 3a [2] 20 }

	condition:
		all of them
}
