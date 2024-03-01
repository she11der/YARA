import "pe"

rule SIGNATURE_BASE_Aspbackdoor_Regdll
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file regdll.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "37096c50-68d0-5412-847a-022062a5ff2a"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2358-L2374"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5c5e16a00bcb1437bfe519b707e0f5c5f63a488d"
		logic_hash = "89606ccf4341ba9451fd1bfbc818bbcd55d45d50e06f09b9f1ecd8efb3c322af"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "exitcode = oShell.Run(\"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, " ascii
		$s3 = "oShell.Run \"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, False" fullword ascii
		$s4 = "EchoB(\"regsvr32.exe exitcode = \" & exitcode)" fullword ascii
		$s5 = "Public Property Get oFS()" fullword ascii

	condition:
		all of them
}
