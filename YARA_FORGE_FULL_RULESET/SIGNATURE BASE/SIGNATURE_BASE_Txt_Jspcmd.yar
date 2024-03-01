rule SIGNATURE_BASE_Txt_Jspcmd : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L594-L608"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1d4e789031b15adde89a4628afc759859e53e353"
		logic_hash = "d2cbf753fbd9e261234e6beb6f79aecb407a368704ae09d907d128d04c242053"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
		$s4 = "out.print(\"Hi,Man 2015\");" fullword ascii

	condition:
		filesize <1KB and 1 of them
}
