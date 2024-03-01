rule SIGNATURE_BASE_Payload_Exe2Hex
{
	meta:
		description = "Detects payload generated by exe2hex"
		author = "Florian Roth (Nextron Systems)"
		id = "c29e4937-cc6a-5265-a3b9-1018228dc956"
		date = "2016-01-15"
		modified = "2023-12-05"
		reference = "https://github.com/g0tmi1k/exe2hex"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/generic_exe2hex_payload.yar#L8-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "91b738f0174a267bbc900d59abcb504d2ae0bac8c287c3b7d1ebfc57374a7ee7"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$a1 = "set /p \"=4d5a" ascii
		$a2 = "powershell -Command \"$hex=" ascii
		$b1 = "set+%2Fp+%22%3D4d5" ascii
		$b2 = "powershell+-Command+%22%24hex" ascii
		$c1 = "echo 4d 5a " ascii
		$c2 = "echo r cx >>" ascii
		$d1 = "echo+4d+5a+" ascii
		$d2 = "echo+r+cx+%3E%3E" ascii

	condition:
		all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}
