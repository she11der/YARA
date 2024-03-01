rule SIGNATURE_BASE_FE_LEGALSTRIKE_RTF : FILE
{
	meta:
		description = "Rtf Phishing Campaign leveraging the CVE 2017-0199 exploit, to point to the domain 2bunnyDOTcom"
		author = "joshua.kim@FireEye. - modified by Florian Roth"
		id = "b62ceffa-445f-517e-b86b-56e47876c6c0"
		date = "2017-06-02"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_apt19.yar#L52-L69"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "af811694076f7d53ee76713538839c4ec82c591518d59d5988dcb893bfd32ffe"
		score = 75
		quality = 85
		tags = "FILE"
		version = ".1"
		filetype = "MACRO"

	strings:
		$lnkinfo = "4c0069006e006b0049006e0066006f"
		$encoded1 = "4f4c45324c696e6b"
		$encoded2 = "52006f006f007400200045006e007400720079"
		$encoded3 = "4f0062006a0049006e0066006f"
		$encoded4 = "4f006c0065"
		$datastore = "\\*\\datastore"

	condition:
		uint32be(0)==0x7B5C7274 and all of them
}
