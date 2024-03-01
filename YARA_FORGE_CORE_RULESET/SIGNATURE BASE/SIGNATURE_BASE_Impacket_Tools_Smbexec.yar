rule SIGNATURE_BASE_Impacket_Tools_Smbexec : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "02208817-2eab-54e2-90cf-44dbf5474607"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L204-L218"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0f424dd5cc525ef0bd9671c4c1b8da0a1ff9eb79056cc081c1ebe7c9bf75fee6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"

	strings:
		$s1 = "logging.config(" ascii
		$s2 = "ssmbexec" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
