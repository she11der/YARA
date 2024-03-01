import "pe"

rule SIGNATURE_BASE_Reflective_DLL_Loader_Aug17_1 : FILE
{
	meta:
		description = "Detects Reflective DLL Loader"
		author = "Florian Roth (Nextron Systems)"
		id = "9a2674f8-5fdb-5a4d-a2b9-41e874939616"
		date = "2017-08-20"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_loaders.yar#L53-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "9ad012dda538d37242c92c6ed16a0fb1cd9252a2884387f8e7d9c80b041c8fea"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f2f85855914345eec629e6fc5333cf325a620531d1441313292924a88564e320"

	strings:
		$x1 = "\\Release\\reflective_dll.pdb" ascii
		$x2 = "reflective_dll.x64.dll" fullword ascii
		$s3 = "DLL Injection" fullword ascii
		$s4 = "?ReflectiveLoader@@YA_KPEAX@Z" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="4bf489ae7d1e6575f5bb81ae4d10862f" or pe.exports("?ReflectiveLoader@@YA_KPEAX@Z") or (1 of ($x*) or 2 of them ))) or (2 of them )
}
