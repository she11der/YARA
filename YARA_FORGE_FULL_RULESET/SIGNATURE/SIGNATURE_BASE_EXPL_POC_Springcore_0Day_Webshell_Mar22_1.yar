rule SIGNATURE_BASE_EXPL_POC_Springcore_0Day_Webshell_Mar22_1 : FILE
{
	meta:
		description = "Detects webshell found after SpringCore exploitation attempts POC script"
		author = "Florian Roth (Nextron Systems)"
		id = "e7047c98-3c60-5211-9ad5-2bfdfb35d493"
		date = "2022-03-30"
		modified = "2023-12-05"
		reference = "https://twitter.com/vxunderground/status/1509170582469943303"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_spring4shell.yar#L36-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "17282b66899356a6051f0b47a7a3f02265737283d760f2256e03a2b934bb63b8"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = ".getInputStream(); int a = -1; byte[] b = new byte[2048];"
		$x2 = "if(\"j\".equals(request.getParameter(\"pwd\")"
		$x3 = ".getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();"

	condition:
		filesize <200KB and 1 of them
}
