rule SIGNATURE_BASE_Docm_In_PDF : FILE
{
	meta:
		description = "Detects an embedded DOCM in PDF combined with OpenAction"
		author = "Florian Roth (Nextron Systems)"
		id = "08dfdfda-8ea5-530d-b89b-560415855080"
		date = "2017-05-15"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/general_officemacros.yar#L52-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "045cde0e8f9e0881c2caece7d5660e165aa67b43bed2ba6d4929951497d76494"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$a1 = /<<\/Names\[\([\w]{1,12}.docm\)/ ascii
		$a2 = "OpenAction" ascii fullword
		$a3 = "JavaScript" ascii fullword

	condition:
		uint32(0)==0x46445025 and all of them
}
