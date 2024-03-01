rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Ver_Jsp
{
	meta:
		description = "Strings from the ver.jsp webshell"
		author = "Fox-IT SRT"
		id = "b2828b84-8934-5111-9345-683a07025070"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_wocao.yar#L355-L372"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ada6de4b07a76e79bb17793cda2b51f96554a35992a73f59c360487638ae3be3"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "String strLogo = request.getParameter(\"id\")"
		$b = "!strLogo.equals(\"256\")"
		$c = "boolean chkos = msg.startsWith"
		$d = "while((c = er.read()) != -1)"
		$e = "out.print((char)c);}in.close()"
		$f = "out.print((char)c);}er.close()"

	condition:
		1 of them
}
