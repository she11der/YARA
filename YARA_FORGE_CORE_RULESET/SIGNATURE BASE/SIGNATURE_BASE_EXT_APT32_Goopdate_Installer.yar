import "pe"

rule SIGNATURE_BASE_EXT_APT32_Goopdate_Installer
{
	meta:
		description = "Detects APT32 installer side-loaded with goopdate.dll"
		author = "Facebook"
		id = "08f3cbda-ccb7-517a-b205-5f71de26c735"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_apt32.yar#L3-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "69730f2c2bb9668a17f8dfa1f1523e0e1e997ba98f027ce98f5cbaa869347383"
		logic_hash = "1dcb3009c5c19ff4e54d82d3a4b99b3431e78664f1660522a781e815d96958c4"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = { 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 33 05 ?? ?? ?? ?? }
		$s1 = "GetProcAddress"
		$s2 = { 8B 4D FC ?? ?? 0F B6 51 0C ?? ?? 8B 4D F0 0F B6 1C 01 33 DA }
		$s3 = "FindNextFileW"
		$s4 = "Process32NextW"

	condition:
		(pe.is_64bit() or pe.is_32bit()) and all of them
}
