rule SIGNATURE_BASE_Impacket_Tools_Sniffer___FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "07051edc-91a8-59d6-87bf-dba98ef28588"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L45-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "77f4a7cdfced27ea342fe0fe6debebb720b7494b3f352465ab2fd92f2b7178ab"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"

	strings:
		$s1 = "ssniffer" fullword ascii
		$s2 = "impacket.dhcp(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and all of them )
}