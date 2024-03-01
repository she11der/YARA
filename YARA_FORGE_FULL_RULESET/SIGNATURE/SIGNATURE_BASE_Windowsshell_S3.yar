rule SIGNATURE_BASE_Windowsshell_S3 : FILE
{
	meta:
		description = "Detects simple Windows shell - file s3.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "064754a7-8639-5dbd-93f3-906662b8e9bc"
		date = "2016-03-26"
		modified = "2023-12-05"
		reference = "https://github.com/odzhan/shells/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_winshells.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		logic_hash = "b9274f909b50247a4f5111a14806faadba7814e26805bef7d61eaaf8be4b46ed"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "\\\\.\\pipe\\%08X" fullword ascii
		$s3 = "get <remote> <local> - download file" fullword ascii
		$s4 = "[ simple remote shell for windows v3" fullword ascii
		$s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s6 = "put <local> <remote> - upload file" fullword ascii
		$s7 = "term                 - terminate remote client" fullword ascii
		$s8 = "[ downloading \"%s\" to \"%s\"" fullword ascii
		$s9 = "-l           Listen for incoming connections" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <150KB and 2 of them ) or (5 of them )
}
