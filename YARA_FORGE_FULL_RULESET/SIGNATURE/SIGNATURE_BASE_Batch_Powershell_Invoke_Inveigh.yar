rule SIGNATURE_BASE_Batch_Powershell_Invoke_Inveigh
{
	meta:
		description = "Detects malicious batch file from NCSC report"
		author = "NCSC"
		id = "c5dab029-6515-5d58-9ccd-bf438ba692d5"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_ncsc_report_04_2018.yar#L109-L124"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0a6b1b29496d4514f6485e78680ec4cd0296ef4d21862d8bf363900a4f8e3fd2"
		logic_hash = "5048a180df301707622e9ad0b949da9e39d2f55f16fc43e7344a8181596a836c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ = "Inveigh.ps1" ascii
		$ = "Invoke-Inveigh" ascii
		$ = "-LLMNR N -HTTP N -FileOutput Y" ascii
		$ = "powershell.exe" ascii

	condition:
		all of them
}
