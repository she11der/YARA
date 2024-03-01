rule SIGNATURE_BASE_Hydra_7_3_Hydra : FILE
{
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "70e9a5bf-ce2d-58ab-8bdc-257e2aa5e917"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2130-L2147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2f82b8bf1159e43427880d70bcd116dc9e8026ad"
		logic_hash = "23194c2df0b8bdedc4fc66c423b0aebb10217de328a194b26560d4cc9a5531e3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
		$s2 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE" ascii
		$s3 = "cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s5 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 1 of them
}
