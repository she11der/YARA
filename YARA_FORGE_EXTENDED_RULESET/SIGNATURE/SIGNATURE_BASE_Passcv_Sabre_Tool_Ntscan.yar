rule SIGNATURE_BASE_Passcv_Sabre_Tool_Ntscan : FILE
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		author = "Florian Roth (Nextron Systems)"
		id = "6ec3371a-2a1c-53d1-b650-d28728db1b40"
		date = "2016-10-20"
		modified = "2023-12-05"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_passcv.yar#L143-L159"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "f2b41c1e6db8c9288663cccbf5659484ed415b403068cc566b31aa044bf0de9e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0f290612b26349a551a148304a0bd3b0d0651e9563425d7c362f30bd492d8665"

	strings:
		$x1 = "NTscan.EXE" fullword wide
		$x2 = "NTscan Microsoft " fullword wide
		$s1 = "admin$" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 2 of them )
}
