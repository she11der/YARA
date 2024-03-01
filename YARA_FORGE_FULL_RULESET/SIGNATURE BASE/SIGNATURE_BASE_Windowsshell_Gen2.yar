rule SIGNATURE_BASE_Windowsshell_Gen2 : FILE
{
	meta:
		description = "Detects simple Windows shell - from files s3.exe, s4.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "8ed8443d-491b-5cb0-b12b-0d25267ba462"
		date = "2016-03-26"
		modified = "2023-12-05"
		reference = "https://github.com/odzhan/shells/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_winshells.yar#L101-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c5ce27554b2ee25b974b567ef5a9ae877906250073da477f0ab5d71d162ac81a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		hash2 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"

	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "get <remote> <local> - download file" fullword ascii
		$s3 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s4 = "put <local> <remote> - upload file" fullword ascii
		$s5 = "term                 - terminate remote client" fullword ascii
		$s6 = "[ uploading \"%s\" to \"%s\"" fullword ascii
		$s7 = "[ error : received %i bytes" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <175KB and 2 of them ) or (5 of them )
}
