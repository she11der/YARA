rule SIGNATURE_BASE_CN_Honker_Tuoku_Script_MSSQL_ : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file MSSQL_.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "35c4f119-6a57-580a-b5ee-c36af0ccc94a"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L326-L342"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7097c21f92306983add3b5b29a517204cd6cd819"
		logic_hash = "4d721fd9711799cf3fd8ba6c300e270ed25faa2fb938ea01464e9bc9a3768e22"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "GetLoginCookie = Request.Cookies(Cookie_Login)" fullword ascii
		$s2 = "if ShellPath=\"\" Then ShellPath = \"c:\\\\windows\\\\system32\\\\cmd.exe\"" fullword ascii
		$s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii

	condition:
		filesize <100KB and all of them
}
