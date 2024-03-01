rule SIGNATURE_BASE_Powershell_In_Word_Doc : FILE
{
	meta:
		description = "Detects a powershell and bypass keyword in a Word document"
		author = "Florian Roth (Nextron Systems)"
		id = "c9d073ff-25c6-5751-92bf-e22ae7cfd5f5"
		date = "2017-06-27"
		modified = "2023-12-05"
		reference = "Internal Research - ME"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_susp.yar#L94-L109"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6a9b295f1c430c285aedc5e6df268ea2023c8bdaccd04cf8a5d021419cd6bd64"
		score = 50
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4fd4a7b5ef5443e939015276fc4bf8ffa6cf682dd95845ef10fdf8158fdd8905"

	strings:
		$s1 = "POwErSHELl.ExE" fullword ascii nocase
		$s2 = "BYPASS" fullword ascii nocase

	condition:
		( uint16(0)==0xcfd0 and filesize <1000KB and all of them )
}
