rule SIGNATURE_BASE_Tools_2015 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file 2015.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "eb2826ab-ef8d-5a93-9ede-f5bbd7ab4ff4"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L327-L344"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8fc67359567b78cadf5d5c91a623de1c1d2ab689"
		logic_hash = "2b93ef42c277fd8415cf89bf1bef3e841c56a2b4aa1507d99b84cd8adc9a0644"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
		$s4 = "System.out.println(Oute.toString());" fullword ascii
		$s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
		$s8 = "HttpURLConnection httpUrl = null;" fullword ascii
		$s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii

	condition:
		filesize <7KB and all of them
}
