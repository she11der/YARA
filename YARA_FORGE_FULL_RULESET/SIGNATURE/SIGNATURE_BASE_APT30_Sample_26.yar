rule SIGNATURE_BASE_APT30_Sample_26 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "aa80a142-c8fc-504e-b475-e9838607bec6"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L681-L700"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e26588113417bf68cb0c479638c9cd99a48e846d"
		logic_hash = "b585687c071dc2dddb888906f47b7af6bc7683e902d3afb42364896e800fac5c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "forcegue" fullword ascii
		$s3 = "Windows\\Cur" fullword ascii
		$s4 = "System Id" fullword ascii
		$s5 = "Software\\Mic" fullword ascii
		$s6 = "utiBy0ToWideCh&$a" fullword ascii
		$s10 = "ModuleH" fullword ascii
		$s15 = "PeekNamed6G" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
