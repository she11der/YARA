rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Yellowspirit
{
	meta:
		description = "Auto-generated rule - file user.tool.yellowspirit.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "b1ca04e5-bac7-5247-b2d4-82c3515c92fc"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L103-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "698b23cc4cc6f319ddef7a93cf7ddc83ffae1d2c2b0a9545011b51e381f8cd0c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a7c4b718fa92934a9182567288146ffa3312d9f3edc3872478c90e0e2814078c"

	strings:
		$s1 = "-l 19.16.1.1 -i 10.0.3.1 -n 2222 -r nscd -x 9999" fullword ascii
		$s2 = "-s PITCH_IP -x PITCH_IP -y RHP-24 TARGET_IP" fullword ascii

	condition:
		1 of them
}
