import "pe"

rule SIGNATURE_BASE_Kekeo_Hacktool : FILE
{
	meta:
		description = "Detects Kekeo Hacktool"
		author = "Florian Roth (Nextron Systems)"
		id = "a4158da8-fc4d-5dc6-b44c-f5325b3bb8ca"
		date = "2017-07-21"
		modified = "2023-12-05"
		reference = "https://github.com/gentilkiwi/kekeo/releases"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L3845-L3860"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "14283064e7c8fcee9cde206d25b43b02876a7a4d5de9da6dab47d7f5ba54f019"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ce92c0bcdf63347d84824a02b7a448cf49dd9f44db2d02722d01c72556a2b767"
		hash2 = "49d7fec5feff20b3b57b26faccd50bc05c71f1dddf5800eb4abaca14b83bba8c"

	strings:
		$x1 = "[ticket %u] session Key is NULL, maybe a TGT without enough rights when WCE dumped it." fullword wide
		$x2 = "ERROR kuhl_m_smb_time ; Invalid! Command: %02x - Status: %08x" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*)))
}
