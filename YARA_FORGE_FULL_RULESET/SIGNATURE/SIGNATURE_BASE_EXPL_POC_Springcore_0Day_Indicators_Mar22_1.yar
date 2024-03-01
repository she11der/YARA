rule SIGNATURE_BASE_EXPL_POC_Springcore_0Day_Indicators_Mar22_1
{
	meta:
		description = "Detects indicators found after SpringCore exploitation attempts and in the POC script"
		author = "Florian Roth (Nextron Systems)"
		id = "297e4b57-f831-56e0-a391-1ffbc9a4d438"
		date = "2022-03-30"
		modified = "2023-12-05"
		reference = "https://twitter.com/vxunderground/status/1509170582469943303"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_spring4shell.yar#L19-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "39fb62ec7953dae0a88e39e73e3ff286fc19cb8f21f8feb869a1875f6ba70cfb"
		score = 70
		quality = 85
		tags = ""

	strings:
		$x1 = "java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di"
		$x2 = "?pwd=j&cmd=whoami"
		$x3 = ".getParameter(%22pwd%22)"
		$x4 = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7B"

	condition:
		1 of them
}
