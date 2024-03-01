rule SIGNATURE_BASE_APT_MAL_Fujinama : FILE
{
	meta:
		description = "Fujinama RAT used by Leonardo SpA Insider Threat"
		author = "ReaQta Threat Intelligence Team"
		id = "b10b1e45-aa6c-53fa-8e02-7a325c3e12fb"
		date = "2021-01-07"
		modified = "2023-12-05"
		reference = "https://reaqta.com/2021/01/fujinama-analysis-leonardo-spa"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fujinama_rat.yar#L1-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9bff8ee5424a939b5278b2d1b349d898d138b9efb3cf783221826abb4d8015ef"
		score = 75
		quality = 51
		tags = "FILE"
		version = "1"

	strings:
		$kaylog_1 = "SELECT" wide ascii nocase
		$kaylog_2 = "RIGHT" wide ascii nocase
		$kaylog_3 = "HELP" wide ascii nocase
		$kaylog_4 = "WINDOWS" wide ascii nocase
		$computername = "computername" wide ascii nocase
		$useragent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)" wide ascii nocase
		$pattern = "'()*+,G-./0123456789:" wide ascii nocase
		$function_1 = "t_save" wide ascii nocase
		$cftmon = "cftmon" wide ascii nocase
		$font = "Tahoma" wide ascii nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
