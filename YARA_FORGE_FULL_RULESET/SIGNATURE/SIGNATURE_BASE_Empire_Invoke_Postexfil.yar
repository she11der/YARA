rule SIGNATURE_BASE_Empire_Invoke_Postexfil : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-PostExfil.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "58d9e057-efde-56ab-9b7e-982342a910e2"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L275-L289"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "74602d1c4986e6392df8845e0ed713499aa3b93c64e9d68e95f9dbaf60fe4299"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "00c0479f83c3dbbeff42f4ab9b71ca5fe8cd5061cb37b7b6861c73c54fd96d3e"

	strings:
		$s1 = "# upload to a specified exfil URI" fullword ascii
		$s2 = "Server path to exfil to." fullword ascii

	condition:
		( uint16(0)==0x490a and filesize <2KB and 1 of them ) or all of them
}
