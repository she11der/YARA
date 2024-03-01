rule SIGNATURE_BASE_CN_Honker_Sig_3389_3389_2 : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file 3389.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "f449f632-3102-5e62-b790-5546698dd663"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L99-L114"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5ff92f39ade12f8ba6cb75dfdc9bb907e49f0ebd"
		logic_hash = "637b3368fac624ca78d2f573b8b937b6b265426d7ed923f3a3d06039663c97ad"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "@del c:\\termsrvhack.dll" fullword ascii
		$s2 = "@del c:\\3389.txt" fullword ascii

	condition:
		filesize <3KB and all of them
}
