rule SIGNATURE_BASE_CN_Honker_Portrecall_Bc : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file bc.pl"
		author = "Florian Roth (Nextron Systems)"
		id = "ea74f260-87e6-5027-b558-628949cae32a"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L308-L324"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2084990406398afd856b2309c7f579d7d61c3767"
		logic_hash = "f51644f195e42b91dae80ba1770aeb40790ea8528b6d09f5fed0f71d93bda5fc"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "print \"[*] Connected to remote host \\n\"; " fullword ascii
		$s1 = "print \"Usage: $0 [Host] [Port] \\n\\n\";  " fullword ascii
		$s5 = "print \"[*] Resolving HostName\\n\"; " fullword ascii

	condition:
		filesize <10KB and all of them
}
