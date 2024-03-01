rule SIGNATURE_BASE_Shellcrew_Streamex_1 : FILE
{
	meta:
		description = "Auto-generated rule"
		author = "Florian Roth (Nextron Systems)"
		id = "26b4cac0-3f2b-5637-86f5-16b7f8afa0e6"
		date = "2017-02-10"
		modified = "2022-12-21"
		reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_shellcrew_streamex.yar#L40-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4da0b8843de87e53243af40700afaab77120531af28dc311d9100bce6721650b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "81f411415aefa5ad7f7ed2365d9a18d0faf33738617afc19215b69c23f212c07"

	strings:
		$x1 = "cmd.exe /c  \"%s\"" fullword wide
		$s3 = "uac\\bin\\install_test.pdb" ascii
		$s5 = "uncompress error:%d %s" fullword ascii
		$s7 = "%s\\AdobeBak\\Proc.dat" fullword wide
		$s8 = "e:\\workspace\\boar" fullword ascii
		$s12 = "$\\data.ini" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 4 of them )
}
