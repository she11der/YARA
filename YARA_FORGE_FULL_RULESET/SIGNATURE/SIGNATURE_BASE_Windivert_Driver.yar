rule SIGNATURE_BASE_Windivert_Driver : FILE
{
	meta:
		description = "Detects WinDivert User-Mode packet capturing driver"
		author = "Florian Roth (Nextron Systems)"
		id = "95e89577-bb5a-5391-9130-155746d4783f"
		date = "2017-10-02"
		modified = "2023-12-05"
		reference = "https://www.reqrypt.org/windivert.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_pua.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "db2933396e015e906114bd04f75a5b5caf0564494224f533a6e00c1fa5421568"
		score = 40
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "33c657fa27b92cfcced66b331cfea7a880460a98cf037e4277faa1420fe59d1c"
		hash2 = "9b834e8f9d117bf2c564a37434973dc0717270ebfac8d8251711905d18da3858"
		hash3 = "5ef707ea68a9bd3a3e568793a0f7d66d166694801ada067d9ebac1d13e53153e"
		hash4 = "df12afa691e529f01c75b3dd734f6b45bf1488dbf90ced218657f0d205bff319"

	strings:
		$s1 = "WinDivertDllEntry" fullword ascii
		$s2 = "WinDivertHelperParseIPv4Address" fullword ascii
		$s3 = "WinDivert (web: http://reqrypt.org/windivert.html)" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and 1 of them )
}
