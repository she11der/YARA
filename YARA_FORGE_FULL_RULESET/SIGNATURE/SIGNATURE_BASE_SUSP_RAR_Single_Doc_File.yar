rule SIGNATURE_BASE_SUSP_RAR_Single_Doc_File : FILE
{
	meta:
		description = "Detects suspicious RAR files that contain nothing but a single .doc file"
		author = "Florian Roth (Nextron Systems)"
		id = "92dc3a5d-d12c-56d3-8531-25b3da1e1595"
		date = "2020-07-11"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_hunting_susp_rar.yar#L3-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bfc8c60c86e65e041976dac9d15c486ad99da930849bd697c869eec0a2626c38"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$s1 = ".doc"

	condition:
		uint16(0)==0x6152 and filesize <4000KB and $s1 at ( uint16(5)+ uint16( uint16(5)+5)+ uint16( uint16(5)+ uint16( uint16(5)+5)+5)-9) and ( uint16(5)+ uint16( uint16(5)+5)+ uint16( uint16(5)+ uint16( uint16(5)+5)+5)+ uint32( uint16(5)+ uint16( uint16(5)+5)+7)> filesize -8)
}
