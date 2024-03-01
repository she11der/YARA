rule SIGNATURE_BASE_CN_Honker_Pk_Pker : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Pker.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "dff0e4fb-6b2e-5fa8-910d-63a9e5030b95"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2166-L2186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "631787f27f27c46f79e58e1accfcc9ecfb4d3a2f"
		logic_hash = "ea29bc82131751f0aaa4f10cc7576a27d243fb7dade03db7ae3dcb029b306505"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "/msadc/..%5c..%5c..%5c..%5cwinnt/system32/cmd.exe" fullword wide
		$s2 = "msadc/..\\..\\..\\..\\winnt/system32/cmd.exe" fullword wide
		$s3 = "--Made by VerKey&Only_Guest&Bincker" fullword wide
		$s4 = ";APPLET;EMBED;FRAMESET;HEAD;NOFRAMES;NOSCRIPT;OBJECT;SCRIPT;STYLE;" fullword wide
		$s5 = " --Welcome to Www.Pker.In Made by V.K" fullword wide
		$s6 = "Report.dat" fullword wide
		$s7 = ".\\Report.dat" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 5 of them
}
