import "pe"

rule SIGNATURE_BASE_Reflective_DLL_Loader_Aug17_4 : FILE
{
	meta:
		description = "Detects Reflective DLL Loader"
		author = "Florian Roth (Nextron Systems)"
		id = "d2a28ea6-a3f7-5ceb-86fd-1e5b7f916a41"
		date = "2017-08-20"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_loaders.yar#L156-L176"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b988ea586589dced18f2165eff431be897b3e96fce2d124f5f41d52b520ccd76"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "205b881701d3026d7e296570533e5380e7aaccaa343d71b6fcc60802528bdb74"
		hash2 = "f76151646a0b94024761812cde1097ae2c6d455c28356a3db1f7905d3d9d6718"

	strings:
		$x1 = "<H1>&nbsp;>> >> >> Keylogger Installed - %s %s << << <<</H1>" fullword ascii
		$s1 = "<H3> ----- Running Process ----- </H3>" fullword ascii
		$s2 = "<H2>Operating system: %s<H2>" fullword ascii
		$s3 = "<H2>System32 dir:  %s</H2>" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them )
}
