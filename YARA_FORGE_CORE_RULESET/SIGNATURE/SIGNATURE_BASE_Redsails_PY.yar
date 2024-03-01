rule SIGNATURE_BASE_Redsails_PY
{
	meta:
		description = "Detects Red Sails Hacktool - Python"
		author = "Florian Roth (Nextron Systems)"
		id = "59d5e784-70ff-5061-9867-54c905ecfd8c"
		date = "2017-10-02"
		modified = "2023-12-05"
		reference = "https://github.com/BeetleChunks/redsails"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_redsails.yar#L27-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4c5426a427e2c25cf9e44ae5f9ec477c9ab11f611d9a0db444c36e7cae176562"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6ebedff41992b9536fe9b1b704a29c8c1d1550b00e14055e3c6376f75e462661"
		hash2 = "5ec20cb99030f48ba512cbc7998b943bebe49396b20cf578c26debbf14176e5e"

	strings:
		$x1 = "Gained command shell on host" fullword ascii
		$x2 = "[!] Received an ERROR in shell()" fullword ascii
		$x3 = "Target IP address with backdoor installed" fullword ascii
		$x4 = "Open backdoor port on target machine" fullword ascii
		$x5 = "Backdoor port to open on victim machine" fullword ascii

	condition:
		1 of them
}
