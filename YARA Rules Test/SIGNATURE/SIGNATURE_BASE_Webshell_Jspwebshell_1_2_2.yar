rule SIGNATURE_BASE_Webshell_Jspwebshell_1_2_2
{
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
		author = "Florian Roth (Nextron Systems)"
		id = "659f5c7d-0a9c-554d-a0ad-e3bcb8c5a1e9"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6449-L6464"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "184fc72b51d1429c44a4c8de43081e00967cf86b"
		logic_hash = "41d937fce969a850a2e4e07eb168becc96a036317a78d620e812707be9466dfc"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
		$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
		$s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
		$s15 = "endPoint=random1.getFilePointer();" fullword
		$s20 = "if (request.getParameter(\"command\") != null) {" fullword

	condition:
		3 of them
}