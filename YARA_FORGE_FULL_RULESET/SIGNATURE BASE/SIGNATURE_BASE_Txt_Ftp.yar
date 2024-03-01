rule SIGNATURE_BASE_Txt_Ftp : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file ftp.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "311de4b0-fa19-545a-8a65-a40b255b5b39"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L554-L573"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3495e6bcb5484e678ce4bae0bd1a420b7eb6ad1d"
		logic_hash = "02eae9b19274ab7b816d7c336017af8f0fdd5273664eb37be92be12661f3ef1f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
		$s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
		$s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
		$s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
		$s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
		$s6 = "ftp -s:d:\\ftp.txt " fullword ascii
		$s7 = "echo bye>>d:\\ftp.txt " fullword ascii

	condition:
		filesize <2KB and 2 of them
}
