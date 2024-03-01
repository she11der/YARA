import "pe"

rule SIGNATURE_BASE_WPR_Loader_EXE : FILE
{
	meta:
		description = "Windows Password Recovery - file loader.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "97fa3efb-9e7a-52ef-9e26-3fdd573d4d30"
		date = "2017-03-15"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3473-L3493"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "26af6fe1b3dfe8e3a48c03a9f6f2033fbc909a677d35159e28b7e9b867ea5542"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e7d158d27d9c14a4f15a52ee5bf8aa411b35ad510b1b93f5e163ae7819c621e2"

	strings:
		$s1 = "Failed to get system process ID" fullword wide
		$s2 = "gLSASS.EXE" fullword wide
		$s3 = "WriteProcessMemory failed" fullword wide
		$s4 = "wow64 process NOT created" fullword wide
		$s5 = "\\ast.exe" wide
		$s6 = "Exit code=%s, status=%d" fullword wide
		$s7 = "VirtualProtect failed" fullword wide
		$s8 = "nSeDebugPrivilege" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 3 of them )
}
