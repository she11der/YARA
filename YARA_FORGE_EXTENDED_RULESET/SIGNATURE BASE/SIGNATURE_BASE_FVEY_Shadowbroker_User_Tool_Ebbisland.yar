rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Ebbisland
{
	meta:
		description = "Auto-generated rule - file user.tool.ebbisland.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "fd312ba2-d590-5007-875c-008553c2b1b9"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L244-L258"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0a45ea3cd6aeea9299ef67ae82c9f4bf929a961695e7cce344aa1737fa4c07b0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "390e776ae15fadad2e3825a5e2e06c4f8de6d71813bef42052c7fd8494146222"

	strings:
		$x1 = "-t 127.0.0.1 -p SERVICE_TCP_PORT -r TARGET_RPC_SERVICE -X"
		$x2 = "-N -A SPECIFIC_SHELLCODE_ADDRESS" fullword ascii

	condition:
		1 of them
}
