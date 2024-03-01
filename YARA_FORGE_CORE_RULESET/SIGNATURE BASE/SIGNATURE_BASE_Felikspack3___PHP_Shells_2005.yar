rule SIGNATURE_BASE_Felikspack3___PHP_Shells_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "91d278d5-e9ec-5a28-9a54-4549b4f0cd07"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7969-L7981"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "97f2552c2fafc0b2eb467ee29cc803c8"
		logic_hash = "4d04174b23c9057acf2618c01cd702eaaec2d3508a8c25dd87fdd320c076a3b1"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp"
		$s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">"

	condition:
		all of them
}
