import "pe"

rule SIGNATURE_BASE_Vssown_VBS
{
	meta:
		description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
		author = "Florian Roth (Nextron Systems)"
		id = "ffbb5faf-3522-50dc-a568-503074ac0636"
		date = "2015-10-01"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3065-L3082"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f49e9d7a07d591330e16fc539bd98d019b47dd8579d0f1ad92fa987790e64189"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
		$s1 = "Select * From Win32_ShadowCopy" ascii
		$s2 = "cmd /C mklink /D " ascii
		$s3 = "ClientAccessible" ascii
		$s4 = "WScript.Shell" ascii
		$s5 = "Win32_Process" ascii

	condition:
		all of them
}
