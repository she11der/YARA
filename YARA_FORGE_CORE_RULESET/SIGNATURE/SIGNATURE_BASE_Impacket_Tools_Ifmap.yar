rule SIGNATURE_BASE_Impacket_Tools_Ifmap : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "e5461916-ec2b-5f65-b938-267483f50bb2"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L77-L91"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "bbe875e03434c040da914e81ec5ef691ba8fd02607631e118d958819d0e94ff5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "20a1f11788e6cc98a76dca2db4691963c054fc12a4d608ac41739b98f84b3613"

	strings:
		$s1 = "bifmap.exe.manifest" fullword ascii
		$s2 = "impacket.dcerpc.v5.epm(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and all of them )
}
