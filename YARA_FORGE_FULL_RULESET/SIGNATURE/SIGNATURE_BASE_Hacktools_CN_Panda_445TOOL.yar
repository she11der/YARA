import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Panda_445TOOL
{
	meta:
		description = "Disclosed hacktool set - file 445TOOL.rar"
		author = "Florian Roth (Nextron Systems)"
		id = "02075631-49cc-5b97-ad8e-92d734a26d34"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1131-L1147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "92050ba43029f914696289598cf3b18e34457a11"
		logic_hash = "69a17bf7735eea946a5326d9535e68b8f010f2a0229875970b1bb15029c6dc4e"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "scan.bat" fullword ascii
		$s1 = "Http.exe" fullword ascii
		$s2 = "GOGOGO.bat" fullword ascii
		$s3 = "ip.txt" fullword ascii

	condition:
		all of them
}
