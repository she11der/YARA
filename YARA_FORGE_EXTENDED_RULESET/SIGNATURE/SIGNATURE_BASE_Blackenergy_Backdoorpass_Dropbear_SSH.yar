rule SIGNATURE_BASE_Blackenergy_Backdoorpass_Dropbear_SSH : FILE
{
	meta:
		description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy"
		author = "Florian Roth (Nextron Systems)"
		id = "60db00dd-72b3-5a28-90de-2a397b1e007b"
		date = "2016-01-03"
		modified = "2023-12-05"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_blackenergy.yar#L71-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
		logic_hash = "3af58d155691d9323458280ad1b933e8e784acafb0974f5f267b93d9b02e825e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "passDs5Bu9Te7" fullword ascii

	condition:
		uint16(0)==0x5a4d and $s1
}
