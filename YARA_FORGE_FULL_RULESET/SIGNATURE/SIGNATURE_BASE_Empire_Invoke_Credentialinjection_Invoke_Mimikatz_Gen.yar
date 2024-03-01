rule SIGNATURE_BASE_Empire_Invoke_Credentialinjection_Invoke_Mimikatz_Gen : FILE
{
	meta:
		description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-Mimikatz.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "d938aadf-6924-5964-9b5a-6bd1b817349f"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L547-L563"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3210b4407c3209a20d74c8c5af66077cc9b902912ae49253883b7acd87eef1f9"
		score = 75
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"

	strings:
		$s1 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle" fullword ascii
		$s2 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <4000KB and 1 of them ) or all of them
}
