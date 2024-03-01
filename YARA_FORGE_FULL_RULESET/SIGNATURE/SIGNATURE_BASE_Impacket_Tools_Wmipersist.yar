rule SIGNATURE_BASE_Impacket_Tools_Wmipersist : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "29bda652-28f0-5ab6-9bc2-411f20ab0dda"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_impacket_tools.yar#L305-L319"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "df0dfaed264e0acc57f74e40addcaf52f6d8e832524eb638b682a358c81da83f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"

	strings:
		$s1 = "swmipersist" fullword ascii
		$s2 = "\\yzHPlU=QA" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
