rule SIGNATURE_BASE_Sofacy_Jun16_Sample3 : FILE
{
	meta:
		description = "Detects Sofacy Malware mentioned in PaloAltoNetworks APT report"
		author = "Florian Roth (Nextron Systems)"
		id = "f97bc840-0d9a-5a9e-9e13-7b7f8acc53a5"
		date = "2016-06-14"
		modified = "2023-12-05"
		reference = "http://goo.gl/mzAa97"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sofacy_jun16.yar#L51-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bdc6fcc30ebd7a966391747e4156a6d94dc9187e8b8898de4c441540ec4e637e"
		score = 85
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c2551c4e6521ac72982cb952503a2e6f016356e02ee31dea36c713141d4f3785"

	strings:
		$s1 = "ASLIiasiuqpssuqkl713h" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and $s1
}
