rule SIGNATURE_BASE_Sysinternals_Tool_Anomaly : FILE
{
	meta:
		description = "SysInternals Tool Anomaly - does not contain Mark Russinovich as author"
		author = "Florian Roth (Nextron Systems)"
		id = "b676726b-7ecd-52ed-bdec-3d81b7596246"
		date = "2016-12-06"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_sysinternals_anomaly.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "760795a51965197bd101ffbf0f7c8cfbbb16d2f443d0941de4a75c8f33f4cad0"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Software\\Sysinternals\\%s" fullword ascii
		$n1 = "Mark Russinovich" wide ascii
		$nfp1 = "<<<Obsolete>>>" fullword wide
		$nfp2 = "BGInfo - Wallpaper text configurator" wide
		$nfp3 = "usage: movefile [source] [dest]" wide
		$nfp4 = "LoadOrder information has been copied" wide
		$nfp5 = "Cache working set cleared" wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and $s1 and not $n1 and not 1 of ($nfp*))
}
