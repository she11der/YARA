rule SIGNATURE_BASE_Poisonivy_Sample_APT_3 : FILE
{
	meta:
		description = "Detects a PoisonIvy Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "e2e0bf75-7704-585f-b2b3-727d14946c76"
		date = "2015-06-03"
		modified = "2023-12-05"
		reference = "VT Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_poisonivy.yar#L60-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "df3e1668ac20edecc12f2c1a873667ea1a6c3d6a"
		logic_hash = "96f8324dcf85f5baa64178774abf17516a9e023dd6fa38e2bce0fe5159a4f704"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\notepad.exe" ascii
		$s1 = "\\RasAuto.dll" ascii
		$s3 = "winlogon.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
