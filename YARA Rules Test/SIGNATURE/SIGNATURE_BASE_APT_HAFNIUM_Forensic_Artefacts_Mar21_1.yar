rule SIGNATURE_BASE_APT_HAFNIUM_Forensic_Artefacts_Mar21_1
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions"
		author = "Florian Roth (Nextron Systems)"
		id = "872822b0-34d9-5ae4-a532-6a8786494fa9"
		date = "2021-03-02"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_hafnium.yar#L35-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "eb86595956092506c2e29373faaf39a3987f9feed36a53b191bedd498db05cbb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "lsass.exe C:\\windows\\temp\\lsass" ascii wide fullword
		$s2 = "c:\\ProgramData\\it.zip" ascii wide fullword
		$s3 = "powercat.ps1'); powercat -c" ascii wide fullword

	condition:
		1 of them
}