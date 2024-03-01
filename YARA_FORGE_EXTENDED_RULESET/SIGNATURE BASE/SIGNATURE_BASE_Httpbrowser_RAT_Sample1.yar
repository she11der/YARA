rule SIGNATURE_BASE_Httpbrowser_RAT_Sample1 : FILE
{
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
		author = "Florian Roth (Nextron Systems)"
		id = "8babf47f-006c-5001-9753-08ac08f5e861"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "http://snip.ly/giNB"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_threatgroup_3390.yar#L50-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "746df577e952e0354342a48fe9f1650e63e3470902e7c5bba36d36fa34ea2bff"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
		hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"

	strings:
		$s0 = "update.hancominc.com" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and $s0
}
