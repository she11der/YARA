rule SIGNATURE_BASE_SUSP_Enablecontent_String_Gen : FILE
{
	meta:
		description = "Detects suspicious string that asks to enable active content in Office Doc"
		author = "Florian Roth (Nextron Systems)"
		id = "d763bc21-2925-55df-85e0-1ee857e921ca"
		date = "2019-02-12"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_office_dropper.yar#L19-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cde995ab0486fdafdc98e36c28a1f786ee7485387158f7337acd5f7dd0e3fed1"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"

	strings:
		$e1 = "Enable Editing" fullword ascii
		$e2 = "Enable Content" fullword ascii
		$e3 = "Enable editing" fullword ascii
		$e4 = "Enable content" fullword ascii

	condition:
		uint16(0)==0xcfd0 and ($e1 in (0..3000) or $e2 in (0..3000) or $e3 in (0..3000) or $e4 in (0..3000) or 2 of them )
}
