rule SIGNATURE_BASE_CN_Honker_Sig_3389_3389 : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file 3389.vbs"
		author = "Florian Roth (Nextron Systems)"
		id = "6d385820-befe-5e2b-8c48-ad90564d5f42"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L83-L97"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f92b74f41a2138cc05c6b6993bcc86c706017e49"
		logic_hash = "32603edd3f188a9f4919795df04112883d7b88da46b13fcd0b0e0065fd4c016b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "success = obj.run(\"cmd /c takeown /f %SystemRoot%\\system32\\sethc.exe&echo y| " ascii

	condition:
		filesize <10KB and all of them
}
