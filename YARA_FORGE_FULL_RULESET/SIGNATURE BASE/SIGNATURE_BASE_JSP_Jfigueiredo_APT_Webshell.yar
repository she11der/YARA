rule SIGNATURE_BASE_JSP_Jfigueiredo_APT_Webshell
{
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "Florian Roth (Nextron Systems)"
		id = "b5080e43-44e2-54fa-b03a-057dc75d14db"
		date = "2014-12-10"
		modified = "2023-12-05"
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L9060-L9073"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7efaca469d09ce7ecba4ed38cb0b07d1b9fc4f45172d2ffb6f5d3259c000fdc5"
		score = 60
		quality = 85
		tags = ""

	strings:
		$a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
		$a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii

	condition:
		all of them
}
