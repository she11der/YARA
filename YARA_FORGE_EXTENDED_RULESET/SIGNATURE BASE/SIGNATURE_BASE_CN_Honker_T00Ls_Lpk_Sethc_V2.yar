rule SIGNATURE_BASE_CN_Honker_T00Ls_Lpk_Sethc_V2 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v2.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "499b251a-e0e1-5550-825d-acab112be74b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1192-L1208"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a995451d9108687b8892ad630a79660a021d670a"
		logic_hash = "979f3fe9795798743f2a57aa3b82a34e304774de58ffda5278991cf5a753a8ba"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "2011-2012 T00LS&RICES" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
