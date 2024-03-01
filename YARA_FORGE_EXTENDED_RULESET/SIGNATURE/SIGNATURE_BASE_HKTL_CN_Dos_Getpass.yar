rule SIGNATURE_BASE_HKTL_CN_Dos_Getpass : FILE
{
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "08635096-474c-5fdf-825e-6c7c8c8d4061"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "Dos_GetPass"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L811-L830"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
		logic_hash = "ea1410984fb1f66422faa943f1f16873f4e0d5ff1afa68c2d28f36889e214a52"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "GetLogonS" ascii
		$s3 = "/showthread.php?t=156643" ascii
		$s8 = "To Run As Administ" ascii
		$s18 = "EnableDebugPrivileg" fullword ascii
		$s19 = "sedebugnameValue" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <890KB and all of them
}
