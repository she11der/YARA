rule SIGNATURE_BASE_JSP_Jfigueiredo_APT_Webshell_2
{
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "Florian Roth (Nextron Systems)"
		id = "91575627-78c1-5ca1-8180-cc4004df88e8"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9075-L9090"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f7fa5872d8eb4ba1d0b26d966d7650d70b1a10c56945d5a5340b8e1cb5d0f5f0"
		score = 60
		quality = 85
		tags = ""

	strings:
		$a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
		$a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
		$s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
		$s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii

	condition:
		all of ($a*) or all of ($s*)
}
