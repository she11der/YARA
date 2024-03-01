rule SIGNATURE_BASE_Malicious_SFX1 : FILE
{
	meta:
		description = "SFX with voicemail content"
		author = "Florian Roth (Nextron Systems)"
		id = "7c29dfb0-bbed-5017-80b4-a5c44024cd70"
		date = "2015-07-20"
		modified = "2023-12-05"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_minidionis.yar#L39-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c0675b84f5960e95962d299d4c41511bbf6f8f5f5585bdacd1ae567e904cb92f"
		logic_hash = "fd7b4c504a52e68fe87eeb9f7066c61ddc47257ac9324a60d219c022d3affbbf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "voicemail" ascii
		$s1 = ".exe" ascii

	condition:
		uint16(0)==0x4b50 and filesize <1000KB and $s0 in (3..80) and $s1 in (3..80)
}
