rule SIGNATURE_BASE_WEBSHELL_Z_Webshell_1
{
	meta:
		description = "Detects Z Webshell from NCSC report"
		author = "NCSC"
		id = "f4b50760-bd3a-5e1f-bf32-50f16a42c381"
		date = "2018-04-06"
		modified = "2023-12-05"
		old_rule_name = "Z_WebShell"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_ncsc_report_04_2018.yar#L176-L192"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "ace12552f3a980f1eed4cadb02afe1bfb851cafc8e58fb130e1329719a07dbf0"
		logic_hash = "1dfc546a7493c1443527ebe74ed8cd2b06ee032b9a3f736b830e16288e616d43"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ = "Z_PostBackJS" ascii wide
		$ = "z_file_download" ascii wide
		$ = "z_WebShell" ascii wide
		$ = "1367948c7859d6533226042549228228" ascii wide

	condition:
		3 of them
}
