import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Burst_Pass
{
	meta:
		description = "Disclosed hacktool set - file pass.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "d8f6784f-80c8-51e2-9d86-40022cd8705d"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1275-L1298"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "55a05cf93dbd274355d798534be471dff26803f9"
		logic_hash = "3a30cc602a66bd87304756311d56e7c698c1edb0b4b209198c589c4792776992"
		score = 60
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "123456.com" fullword ascii
		$s1 = "123123.com" fullword ascii
		$s2 = "360.com" fullword ascii
		$s3 = "123.com" fullword ascii
		$s4 = "juso.com" fullword ascii
		$s5 = "sina.com" fullword ascii
		$s7 = "changeme" fullword ascii
		$s8 = "master" fullword ascii
		$s9 = "google.com" fullword ascii
		$s10 = "chinanet" fullword ascii
		$s12 = "lionking" fullword ascii

	condition:
		all of them
}
