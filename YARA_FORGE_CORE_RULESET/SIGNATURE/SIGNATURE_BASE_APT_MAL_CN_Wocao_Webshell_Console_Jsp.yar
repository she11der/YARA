rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Console_Jsp
{
	meta:
		description = "Strings from the console.jsp webshell"
		author = "Fox-IT SRT"
		id = "1afdfc34-d2e3-58c7-80ea-ee5632e42469"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L318-L335"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e70c15ef10b63a011edbcedc773a8e2917fd915c3ecc273c3bf2b78eb10fc570"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "String strLogo = request.getParameter(\"image\")"
		$b = "!strLogo.equals(\"web.gif\")"
		$c = "<font color=red>Save Failed!</font>"
		$d = "<font color=red>Save Success!</font>"
		$e = "Save path:<br><input type=text"
		$f = "if (newfile.exists() && newfile.length()>0) { out.println"

	condition:
		1 of them
}
