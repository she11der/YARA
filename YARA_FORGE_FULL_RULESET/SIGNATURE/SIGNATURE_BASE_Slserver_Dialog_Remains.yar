rule SIGNATURE_BASE_Slserver_Dialog_Remains : FILE
{
	meta:
		description = "Searches for related dialog remnants."
		author = "Matt Brooks, @cmatthewbrooks / modified by Florian Roth"
		id = "cf199d25-ce5e-52c2-88de-32a48dee4c6f"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_between-hk-and-burma.yar#L106-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5b18f4a6c54b456ae697e9639e8c3041fd4f3141d89850c3e1d3d4e220c3cea3"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$slserver = "SLServer" wide fullword
		$fp1 = "Dell Inc." wide fullword
		$fp2 = "ScriptLogic Corporation" wide
		$extra1 = "SLSERVER" wide fullword
		$extra2 = "\\SLServer.pdb" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and not 1 of ($fp*) and 1 of ($extra*) and $slserver
}
