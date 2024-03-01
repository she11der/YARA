rule SIGNATURE_BASE_Uacelevator : FILE
{
	meta:
		description = "UACElevator bypassing UAC - file UACElevator.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "629b1a92-726d-5713-ae3d-74cc8a1e52ad"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "https://github.com/MalwareTech/UACElevator"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/exploit_uac_elevators.yar#L66-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "fd29d5a72d7a85b7e9565ed92b4d7a3884defba6"
		logic_hash = "8215746b2c84a5500221580969fb2eac8ee11cbb5af4ba5bf2dbd1def65b8745"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "\\UACElevator.pdb" ascii
		$s1 = "%userprofile%\\Downloads\\dwmapi.dll" fullword ascii
		$s2 = "%windir%\\system32\\dwmapi.dll" fullword ascii
		$s3 = "Infection module: %s" fullword ascii
		$s4 = "Could not save module to %s" fullword ascii
		$s5 = "%s%s%p%s%ld%s%d%s" fullword ascii
		$s6 = "Stack area around _alloca memory reserved by this function is corrupted" fullword ascii
		$s7 = "Stack around the variable '" fullword ascii
		$s8 = "MSVCR120D.dll" fullword wide
		$s9 = "Address: 0x" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <172KB and ($x1 or 8 of ($s*))
}
