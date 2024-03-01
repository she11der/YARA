rule SIGNATURE_BASE_HKTL_CN_Project1 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Project1.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "12cc7a82-d7a9-58c6-b283-3bb0df477cd8"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "Project1"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L899-L916"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
		logic_hash = "c26590f13a185eb42a27d27e6b5996f7fdf4d5c146fb74062686f356ec4db47d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
		$s2 = "Password.txt" fullword ascii
		$s3 = "LoginPrompt" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and all of them
}
