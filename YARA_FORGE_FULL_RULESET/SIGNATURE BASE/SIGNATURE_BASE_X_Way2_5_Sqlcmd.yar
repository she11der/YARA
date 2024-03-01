rule SIGNATURE_BASE_X_Way2_5_Sqlcmd : FILE
{
	meta:
		description = "Chinese Hacktool Set - file sqlcmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c6b4dae2-38cb-5cf9-b980-df5ebefbe7ad"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2296-L2324"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5152a57e3638418b0d97a42db1c0fc2f893a2794"
		logic_hash = "59fd25a786d56885e456fca154800a8313cd04a23fd9374361cc37b86be109a1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
		$s4 = "kernel32.dll" fullword ascii
		$s5 = "VirtualAlloc" fullword ascii
		$s6 = "VirtualFree" fullword ascii
		$s7 = "VirtualProtect" fullword ascii
		$s8 = "ExitProcess" fullword ascii
		$s9 = "user32.dll" fullword ascii
		$s16 = "MessageBoxA" fullword ascii
		$s10 = "wsprintfA" fullword ascii
		$s11 = "kernel32.dll" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "GetModuleHandleA" fullword ascii
		$s14 = "LoadLibraryA" fullword ascii
		$s15 = "odbc32.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <23KB and filesize >20KB and all of them
}
