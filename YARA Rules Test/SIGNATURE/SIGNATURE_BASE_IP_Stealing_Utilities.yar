rule SIGNATURE_BASE_IP_Stealing_Utilities
{
	meta:
		description = "Auto-generated rule on file IP Stealing Utilities.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "3a947e9c-d707-5819-88f2-059585750048"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L261-L272"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "65646e10fb15a2940a37c5ab9f59c7fc"
		logic_hash = "38958edeee6e140e11267cdd7899ad517799dbce33ac267d51dea0f8aecfa1ee"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "DarkKnight"
		$s9 = "IPStealerUtilities"

	condition:
		all of them
}