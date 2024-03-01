rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Webinfo
{
	meta:
		description = "Generic strings from webinfo.war webshells"
		author = "Fox-IT SRT"
		id = "b8477f62-f3f6-5526-b0e3-9b794fefaa1f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L374-L394"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "711737a56067f24f422cc7d5aeba4389741fe18a0e66f2715fce626c3b6aef19"
		score = 75
		quality = 85
		tags = ""

	strings:
		$var1 = "String strLogo = request.getParameter"
		$var2 = "String content = request.getParameter(\"content\");"
		$var3 = "String basePath=request.getScheme()"
		$var4 = "!strLogo.equals("
		$var5 = "if(path!=null && !path.equals(\"\") && content!=null"
		$var6 = "File newfile=new File(path);"
		$str1 = "Save Success!"
		$str2 = "Save Failed!"

	condition:
		2 of ($var*) or ( all of ($str*) and 1 of ($var*))
}
