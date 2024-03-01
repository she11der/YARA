rule SIGNATURE_BASE_CN_Honker_Webshell__Injection_Jmcook_Jmpost_Manualinjection : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files Injection.exe, jmCook.asp, jmPost.asp, ManualInjection.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "e154ecb5-9d56-520a-b76a-635a8864f0a8"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L923-L942"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0f3a4f81326154a6a6ac448d18be29ad534917bc39aba26cc458f06b43001681"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
		hash1 = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
		hash2 = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
		hash3 = "e83d427f44783088a84e9c231c6816c214434526"

	strings:
		$s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii
		$s2 = "strReturn=Replace(strReturn,chr(43),\"%2B\")  'JMDCW" fullword ascii

	condition:
		filesize <7342KB and all of them
}
