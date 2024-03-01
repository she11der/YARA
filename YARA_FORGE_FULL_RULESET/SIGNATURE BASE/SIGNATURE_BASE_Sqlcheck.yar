import "pe"

rule SIGNATURE_BASE_Sqlcheck
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcheck.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a72d38ef-b2e7-5051-8538-724d9e95fa6a"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2399-L2416"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5a5778ac200078b627db84fdc35bf5bcee232dc7"
		logic_hash = "e9c1d7cabe7236e059f4bfec917ca00c47a3db955746ebfcda0f5e733de359c7"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Power by eyas<cooleyas@21cn.com>" fullword ascii
		$s3 = "\\ipc$ \"\" /user:\"\"" fullword ascii
		$s4 = "SQLCheck can only scan a class B network. Try again." fullword ascii
		$s14 = "Example: SQLCheck 192.168.0.1 192.168.0.254" fullword ascii
		$s20 = "Usage: SQLCheck <StartIP> <EndIP>" fullword ascii

	condition:
		3 of them
}
