rule SIGNATURE_BASE_S4U : FILE
{
	meta:
		description = "Detects s4u executable which allows the creation of a cmd.exe with the context of any user without requiring the password. - file s4u.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0d746311-56fe-538c-946c-3a3dd1603adc"
		date = "2015-06-05"
		modified = "2023-12-05"
		reference = "https://github.com/aurel26/s-4-u-for-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/exploit_uac_elevators.yar#L92-L139"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cfc18f3d5306df208461459a8e667d89ce44ed77"
		logic_hash = "b1882710f2514fb44ff01631636c0a66beef620c8bea644ebe05cd5385a9e494"
		score = 50
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x0 = "s4u.exe Domain\\Username [Extra SID]" fullword ascii
		$x1 = "\\Release\\s4u.pdb" ascii
		$s0 = "CreateProcessAsUser failed (error %u)." fullword ascii
		$s1 = "GetTokenInformation failed (error: %u)." fullword ascii
		$s2 = "LsaLogonUser failed (error 0x%x)." fullword ascii
		$s3 = "LsaLogonUser: OK, LogonId: 0x%x-0x%x" fullword ascii
		$s4 = "LookupPrivilegeValue failed (error: %u)." fullword ascii
		$s5 = "The token does not have the specified privilege (%S)." fullword ascii
		$s6 = "Unable to parse command line." fullword ascii
		$s7 = "Unable to find logon SID." fullword ascii
		$s8 = "AdjustTokenPrivileges failed (error: %u)." fullword ascii
		$s9 = "AdjustTokenPrivileges (%S): OK" fullword ascii
		$g1 = "%systemroot%\\system32\\cmd.exe" wide
		$g2 = "SeTcbPrivilege" wide
		$g3 = "winsta0\\default" wide
		$g4 = ".rsrc"
		$g5 = "HeapAlloc"
		$g6 = "GetCurrentProcess"
		$g7 = "HeapFree"
		$g8 = "GetProcessHeap"
		$g9 = "ExpandEnvironmentStrings"
		$g10 = "ConvertStringSidToSid"
		$g11 = "LookupPrivilegeValue"
		$g12 = "AllocateLocallyUniqueId"
		$g13 = "ADVAPI32.dll"
		$g14 = "LsaLookupAuthenticationPackage"
		$g15 = "Secur32.dll"
		$g16 = "MSVCR120.dll"

	condition:
		uint16(0)==0x5a4d and filesize <60KB and (1 of ($x*) or all of ($s*) or all of ($g*))
}
