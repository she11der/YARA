rule SIGNATURE_BASE_CN_Honker_Injection_Transit_Jmcook : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file jmCook.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "468abb0e-a163-5fc5-b6a1-896fc04b8570"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L116-L131"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
		logic_hash = "f7a9aca65b92d4b9c787d83a421b54a23844fa8e061c6c627ddde8ab5b7f4396"
		score = 70
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = ".Open \"POST\",PostUrl,False" fullword ascii
		$s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii

	condition:
		filesize <9KB and all of them
}
