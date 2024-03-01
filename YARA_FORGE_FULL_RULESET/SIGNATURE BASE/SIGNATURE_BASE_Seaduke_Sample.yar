rule SIGNATURE_BASE_Seaduke_Sample : FILE
{
	meta:
		description = "SeaDuke Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "011a303b-b051-519f-9687-668c9bcd15ca"
		date = "2015-07-14"
		modified = "2023-12-05"
		reference = "http://goo.gl/MJ0c2M"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_seaduke_unit42.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d2e570129a12a47231a1ecb8176fa88a1bf415c51dabd885c513d98b15f75d4e"
		logic_hash = "3bec2bedaafddd17ee65747f8be773287eda784bdfa8fc11e8378737139ef94e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "bpython27.dll" fullword ascii
		$s1 = "email.header(" ascii
		$s2 = "LogonUI.exe" fullword wide
		$s3 = "Crypto.Cipher.AES(" ascii
		$s4 = "mod is NULL - %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and all of them
}
