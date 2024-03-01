rule SIGNATURE_BASE_Chinachopper_Generic : FILE
{
	meta:
		description = "China Chopper Webshells - PHP and ASPX"
		author = "Florian Roth (Nextron Systems)"
		id = "2473cef1-88cf-5b76-a87a-2978e6780b4f"
		date = "2015-03-10"
		modified = "2022-10-27"
		reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_webshell_chinachopper.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "34cb81b077d6dae5b4565001b2ab28897c6c554f00aa102601fb9c416c6c0f09"
		score = 75
		quality = 35
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x_aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/
		$x_php = /<?php.\@eval\(\$_POST./
		$fp1 = "GET /"
		$fp2 = "POST /"

	condition:
		filesize <300KB and 1 of ($x*) and not 1 of ($fp*)
}
