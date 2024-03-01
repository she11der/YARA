rule SIGNATURE_BASE_Sekurlsa : FILE
{
	meta:
		description = "Chinese Hacktool Set - file sekurlsa.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "b65dc578-e5a1-57e6-bd98-2c45cd07e857"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L123-L139"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		logic_hash = "dea05c7f19a834cc936c452ca2f6f4286e6c3dae002747c27913960199451c3f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
		$s3 = "SECURITY\\Policy\\Secrets" fullword wide
		$s4 = "Injection de donn" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1150KB and all of them
}
