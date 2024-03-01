rule SIGNATURE_BASE_APT17_Sample_FXSST_DLL : FILE
{
	meta:
		description = "Detects Samples related to APT17 activity - file FXSST.DLL"
		author = "Florian Roth (Nextron Systems)"
		id = "e4b9b25e-8895-5ba5-b706-bfb6892c16ae"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "https://goo.gl/ZiJyQv"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt17_malware.yar#L10-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "52f1add5ad28dc30f68afda5d41b354533d8bce3"
		logic_hash = "51d6da6c3ec46dc9e991a6a36de6d79626f1859296cda65e9027951c13aa4cd5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Microsoft? Windows? Operating System" fullword wide
		$x2 = "fxsst.dll" fullword ascii
		$y1 = "DllRegisterServer" fullword ascii
		$y2 = ".cSV" fullword ascii
		$s1 = "GetLastActivePopup"
		$s2 = "Sleep"
		$s3 = "GetModuleFileName"
		$s4 = "VirtualProtect"
		$s5 = "HeapAlloc"
		$s6 = "GetProcessHeap"
		$s7 = "GetCommandLine"

	condition:
		uint16(0)==0x5a4d and filesize <800KB and ( all of ($x*) or all of ($y*)) and all of ($s*)
}
