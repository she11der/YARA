import "pe"

rule SIGNATURE_BASE_Disclosed_0Day_Pocs_Lpe : FILE
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		author = "Florian Roth (Nextron Systems)"
		id = "d3693d1d-6085-5e62-8f0b-dde5b14758b7"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "Disclosed 0day Repos"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3688-L3709"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "77d72792d7fcf2c54b36d124448e928f306981296715e583d346ccd101e22fc7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e10ee278f4c86d6ee1bd93a7ed71d4d59c0279381b00eb6153aedfb3a679c0b5"
		hash2 = "a5916cefa0f50622a30c800e7f21df481d7a3e1e12083fef734296a22714d088"
		hash3 = "5b701a5b5bbef7027711071cef2755e57984bfdff569fe99efec14a552d8ee43"

	strings:
		$x1 = "msiexec /f c:\\users\\%username%\\downloads\\" ascii
		$x2 = "c:\\users\\%username%\\downloads\\bat.bat" fullword ascii
		$x3 = "\\payload.msi /quiet" ascii
		$x4 = "\\payload2\\WindowsTrustedRTProxy.sys" wide
		$x5 = "\\payload2" wide
		$x6 = "\\payload" wide
		$x7 = "WindowsTrustedRTProxy.sys /grant:r administrators:RX" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <70KB and 1 of them )
}
