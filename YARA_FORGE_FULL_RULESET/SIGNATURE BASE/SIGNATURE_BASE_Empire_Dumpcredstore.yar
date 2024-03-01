rule SIGNATURE_BASE_Empire_Dumpcredstore : FILE
{
	meta:
		description = "Detects Empire component - file dumpCredStore.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "cdb87ed4-fa90-5724-b37d-97cf8e4b8326"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L192-L207"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7136920e531d7ab621e743c5c89c0d817fe453108878e3c808814ca48ad57fb3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c1e91a5f9cc23f3626326dab2dcdf4904e6f8a332e2bce8b9a0854b371c2b350"

	strings:
		$x1 = "[DllImport(\"Advapi32.dll\", SetLastError = true, EntryPoint = \"CredReadW\"" ascii
		$s12 = "[String] $Msg = \"Failed to enumerate credentials store for user '$Env:UserName'\"" fullword ascii
		$s15 = "Rtn = CredRead(\"Target\", CRED_TYPE.GENERIC, out Cred);" fullword ascii

	condition:
		( uint16(0)==0x233c and filesize <40KB and 1 of them ) or all of them
}
