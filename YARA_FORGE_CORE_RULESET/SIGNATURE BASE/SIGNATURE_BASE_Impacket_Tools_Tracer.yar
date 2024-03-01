rule SIGNATURE_BASE_Impacket_Tools_Tracer : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "aea71154-5e19-522f-93b0-ff43fee0c5c0"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L11-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "f851f20243e95fdab66f048c21d417ddb17e1c35e9b6be8219afdfee8c1e0291"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e300339058a885475f5952fb4e9faaa09bb6eac26757443017b281c46b03108b"

	strings:
		$s1 = "btk85.dll" fullword ascii
		$s2 = "btcl85.dll" fullword ascii
		$s3 = "xtk\\unsupported.tcl" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <21000KB and all of them )
}
