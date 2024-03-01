rule SIGNATURE_BASE_SUSP_LNK_Suspiciouscommands : FILE
{
	meta:
		description = "Detects LNK file with suspicious content"
		author = "Florian Roth (Nextron Systems)"
		id = "8bfb1322-8e33-50bc-a389-2d8bdfec9ca7"
		date = "2018-09-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_susp_lnk_files.yar#L20-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a0380927ebc89e46f9138e01f154113c5e23680cea9b117b47406003ea565c1e"
		score = 60
		quality = 81
		tags = "FILE"

	strings:
		$s1 = " -decode " ascii wide
		$s2 = " -enc " ascii wide
		$s3 = " -w hidden " ascii wide
		$s4 = " -ep bypass " ascii wide
		$s5 = " -noni " ascii nocase wide
		$s7 = " -noprofile " ascii wide
		$s8 = ".DownloadString(" ascii wide
		$s9 = ".DownloadFile(" ascii wide
		$s10 = "IEX(" ascii wide
		$s11 = "iex(" ascii wide
		$s12 = "WScript.shell" ascii wide fullword nocase
		$s13 = " -nop " ascii wide
		$s14 = "&tasklist>"
		$s15 = "setlocal EnableExtensions DisableDelayedExpansion"
		$s16 = "echo^ set^"
		$s17 = "del /f /q "
		$s18 = " echo | start "
		$s19 = "&& echo "
		$s20 = "&&set "
		$s21 = "%&&@echo off "

	condition:
		uint16(0)==0x004c and 1 of them
}
