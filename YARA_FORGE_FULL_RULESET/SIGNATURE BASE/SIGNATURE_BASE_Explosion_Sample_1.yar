rule SIGNATURE_BASE_Explosion_Sample_1 : FILE
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Florian Roth (Nextron Systems)"
		id = "dcf28185-75a8-5c9f-9f60-edb8dc187e16"
		date = "2015-04-03"
		modified = "2023-12-05"
		reference = "http://goo.gl/5vYaNb"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_volatile_cedar.yar#L14-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c97693ecb36247bdb44ab3f12dfeae8be4d299bb"
		logic_hash = "f559880c182cf8061d640f60f18fe607d88a1f22216d93ff1d0ece720bcc94a7"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
		$s9 = "WinAutologon From Winlogon Reg" fullword ascii
		$s10 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" fullword ascii
		$s11 = "IE:Password-Protected sites" fullword ascii
		$s12 = "\\his.sys" ascii
		$s13 = "HTTP Password" fullword ascii
		$s14 = "\\data.sys" ascii
		$s15 = "EL$_RasDefaultCredentials#0" fullword wide
		$s17 = "Office Outlook HTTP" fullword ascii
		$s20 = "Hist :<b> %ws</b>  :%s </br></br>" fullword ascii

	condition:
		all of them and uint16(0)==0x5A4D
}
