rule SIGNATURE_BASE_Windowsshell_S4 : FILE
{
	meta:
		description = "Detects simple Windows shell - file s4.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "838771dc-f885-5332-9813-2bc01af8e5fe"
		date = "2016-03-26"
		modified = "2023-12-05"
		reference = "https://github.com/odzhan/shells/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_winshells.yar#L55-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		logic_hash = "fff280debdd32a736e37a73800f226bf6def5dd107abd1d9237d92904622c9ec"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "\\\\.\\pipe\\%08X" fullword ascii
		$s3 = "get <remote> <local> - download file" fullword ascii
		$s4 = "[ simple remote shell for windows v4" fullword ascii
		$s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s6 = "[ downloading \"%s\" to \"%s\"" fullword ascii
		$s7 = "[ uploading \"%s\" to \"%s\"" fullword ascii
		$s8 = "-l           Listen for incoming connections" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <175KB and 2 of them ) or (5 of them )
}
