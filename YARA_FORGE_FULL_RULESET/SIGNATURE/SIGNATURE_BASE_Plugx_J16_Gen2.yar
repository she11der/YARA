rule SIGNATURE_BASE_Plugx_J16_Gen2 : FILE
{
	meta:
		description = "Detects PlugX Malware Samples from June 2016"
		author = "Florian Roth (Nextron Systems)"
		id = "28e9cbb9-cd60-555d-b033-4e2bf293adf2"
		date = "2016-06-08"
		modified = "2023-12-05"
		reference = "VT Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_win_plugx.yar#L42-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8fbe90cbff5d408d26b0a5ace6833a0e3100d11ff544184d9ccc2f39ee806de9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "XPlugKeyLogger.cpp" fullword ascii
		$s2 = "XPlugProcess.cpp" fullword ascii
		$s4 = "XPlgLoader.cpp" fullword ascii
		$s5 = "XPlugPortMap.cpp" fullword ascii
		$s8 = "XPlugShell.cpp" fullword ascii
		$s11 = "file: %s, line: %d, error: [%d]%s" fullword ascii
		$s12 = "XInstall.cpp" fullword ascii
		$s13 = "XPlugTelnet.cpp" fullword ascii
		$s14 = "XInstallUAC.cpp" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and (2 of ($s*))) or (5 of them )
}
