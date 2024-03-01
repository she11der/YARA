rule SIGNATURE_BASE_Webshell_Jspwebshell_1_2
{
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
		author = "Florian Roth (Nextron Systems)"
		id = "dfd8c88d-4fe2-5786-9d71-65dba525c358"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L5992-L6008"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0bed4a1966117dd872ac9e8dceceb54024a030fa"
		logic_hash = "13e696c1c671d7fda832c84f150e3f41ed55bf888c4bebfeb06ea68d6be65527"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
		$s1 = "String password=request.getParameter(\"password\");" fullword
		$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
		$s7 = "String editfile=request.getParameter(\"editfile\");" fullword
		$s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
		$s12 = "password = (String)session.getAttribute(\"password\");" fullword

	condition:
		3 of them
}
