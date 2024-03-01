rule SIGNATURE_BASE_Hytop_Caseswitch_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0f2b8e71-1c11-5efe-bee7-146168aec369"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7779-L7797"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "8bf667ee9e21366bc0bd3491cb614f41"
		logic_hash = "0ecf28b5abb918cd1d8f38b76019dddf19dff5dbb114f16ef6ec9b46cb590a46"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "MSComDlg.CommonDialog"
		$s2 = "CommonDialog1"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s5 = "EVENT_SINK_AddRef"
		$s6 = "By Marcos"
		$s7 = "EVENT_SINK_QueryInterface"
		$s8 = "MethCallEngine"

	condition:
		all of them
}
