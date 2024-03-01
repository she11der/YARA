rule SIGNATURE_BASE_Phyton_Shell_Py
{
	meta:
		description = "Semi-Auto-generated  - file Phyton Shell.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "2f55d60d-94f3-508d-a2d0-5ab59e3fdab3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4640-L4653"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "92b3c897090867c65cc169ab037a0f55"
		logic_hash = "ac16a95cd1fb09c93b315e3cd7d57c1ebec322b641f515854fb73a61393dd365"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()" fullword
		$s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ" fullword
		$s3 = "print \"error; help: head -n 16 d00r.py\"" fullword
		$s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST" fullword

	condition:
		1 of them
}
